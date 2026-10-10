#![doc = include_str!("../README.md")]

extern crate ts_netstack_smoltcp as netstack;

use std::sync::Arc;

use kameo::message::Context;
use tokio::sync::Mutex;

use crate::{
    control_runner::ControlRunner, dataplane::DataplaneActor, env::RegForwarded,
    multiderp::Multiderp, netstack_actor::NetstackActor, peer_tracker::PeerTracker,
};

/// Control runner.
pub mod control_runner;
mod dataplane;
mod derp_latency;
mod direct;
mod disco;
pub mod env;
mod error;
mod multiderp;
mod netmon;
mod netstack_actor;
pub mod options;
mod packetfilter;
mod path_discoverer;
pub mod peer_tracker;
mod registry;
mod retained_bus;
mod route_updater;
mod src_filter;
mod stunner;
mod task;

pub(crate) use env::Env;
pub use error::{Error, ErrorKind};
pub use kameo::actor::{ActorRef, Spawn};
pub use registry::Registry;
pub use task::{ErasedTask, Task};

/// The runtime for a tailscale device.
pub struct Runtime {
    env: Env,
}

/// Configuration for starting a [`Runtime`].
#[derive(Debug, Clone)]
pub struct Config {
    /// The control configuration to use.
    pub control_config: ts_control::Config,
    /// The auth key to use to connect to the control server, cleared from
    /// memory when it is dropped.
    pub auth_key: Option<zeroize::Zeroizing<String>>,
    /// The keys to use.
    pub keys: ts_keys::NodeState,
    /// ⛔ **Runtime options; default is stock behavior.** `no_udp` gates the
    /// UDP actors, `derp` selects the transport and the lab pin, `proxy`
    /// routes every outbound TCP path through CONNECT.
    pub options: options::RuntimeOptions,
}

impl kameo::Actor for Runtime {
    type Error = Error;
    type Args = Config;

    async fn on_start(config: Config, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        // ⛔ The proxy feeds the shared CONNECT dialer before any actor dials:
        // control, DERP and latency all route through it when set.
        config.options.apply_proxy();
        let env = Env::new(config.keys, config.options.clone());
        let no_udp = config.options.no_udp;

        env.bus.link(&slf).await;
        env.scheduler.link(&slf).await;
        env.registry.link(&slf).await;

        #[cfg(feature = "console")]
        {
            // Runs detached.
            if let Err(e) =
                kameo::console::serve((core::net::Ipv4Addr::new(127, 0, 0, 1), 9999)).await
            {
                tracing::error!(error = %e, "console died");
            };
        }

        DataplaneActor::supervise(&slf, env.clone()).spawn().await;

        let (netstack_id, netstack_up, netstack_down) = env
            .ask::<DataplaneActor, _>(None, dataplane::NewOverlayTransport, true)
            .await?;

        disco::Disco::supervise(&slf, env.clone()).spawn().await;

        Multiderp::supervise(&slf, env.clone()).spawn().await;
        // ⛔ Gated on `!no_udp`: on the target there is no UDP and no TUN, so
        // a UDP bind is a failure at best and a panic at worst — and the
        // DERP-only path needs none of these actors (see the stage-2 report:
        // the transport map builds from the netmap's DERP map alone).
        if !no_udp {
            direct::DirectActor::supervise(&slf, env.clone())
                .spawn()
                .await;
        }

        route_updater::RouteUpdater::supervise(&slf, (env.clone(), netstack_id))
            .spawn()
            .await;
        packetfilter::PacketfilterUpdater::supervise(&slf, env.clone())
            .spawn()
            .await;
        src_filter::SourceFilterUpdater::supervise(&slf, env.clone())
            .spawn()
            .await;
        // ⛔ Gated with the UDP set: with no DirectActor there is nothing to
        // discover paths for, and STUN has no servers to ask. PathDiscoverer
        // stays: it is inert without `NewEndpoints` and the report keeps it.
        if !no_udp {
            stunner::Stunner::supervise(&slf, env.clone()).spawn().await;
        }
        path_discoverer::PathDiscoverer::supervise(&slf, env.clone())
            .spawn()
            .await;

        // ⛔ netmon binds AF_NETLINK, whose permissibility on the target is
        // UNKNOWN (the sandprobe never tried it). Gated with the UDP set:
        // DERP-only needs no interface watcher.
        if !no_udp {
            if let Some(mon) = ts_netmon::platform_mon() {
                netmon::NetmonActor::supervise(&slf, (env.clone(), Arc::new(mon)))
                    .spawn()
                    .await;
            }
        }

        PeerTracker::supervise(&slf, env.clone()).spawn().await;

        NetstackActor::supervise(
            &slf,
            (
                env.clone(),
                netstack::netcore::Config {
                    tcp_buffer_size: 64 * 1024,
                    command_channel_capacity: Some(128),
                    ..Default::default()
                },
                netstack_id,
                netstack_up,
                Arc::new(Mutex::new(netstack_down)),
            ),
        )
        .spawn()
        .await;

        control_runner::DialerActor::supervise(&slf, env.clone())
            .spawn()
            .await;

        ControlRunner::supervise(
            &slf,
            control_runner::Params {
                config: config.control_config,
                auth_key: config.auth_key,
                env: env.clone(),
            },
        )
        .spawn()
        .await;

        // Actors we forward messages for:
        env.wait::<ControlRunner>(None).await?;
        env.wait::<NetstackActor>(None).await?;
        env.wait::<PeerTracker>(None).await?;

        Ok(Self { env })
    }
}

macro_rules! forward {
    ($actor:ty, $($msg:ty),* $(,)?) => {
        $(
            pub use $msg;

            impl kameo::message::Message<$msg> for Runtime {
                type Reply = RegForwarded<$actor, $msg>;

                async fn handle(
                    &mut self,
                    msg: $msg,
                    ctx: &mut Context<Self, Self::Reply>,
                ) -> RegForwarded<$actor, $msg> {
                    self.env.forward(ctx, None, msg).await
                }
            }
        )*
    };
}

forward!(NetstackActor, netstack_actor::GetChannel);
forward!(
    ControlRunner,
    control_runner::Ipv4,
    control_runner::Ipv6,
    control_runner::SelfNode,
    control_runner::AuthUrl,
    control_runner::Logout,
);

/// Ask the control runner of `runtime` to log this node out (podssh's patch 0016). A runtime that
/// cannot take the request has stopped.
pub async fn logout(runtime: &ActorRef<Runtime>) -> Result<(), ts_control::LogoutError> {
    use kameo::error::SendError::HandlerError;

    // The runtime's forward and the registry's each wrap the runner's own error.
    match runtime.ask(control_runner::Logout).await {
        Ok(()) => Ok(()),
        Err(HandlerError(HandlerError(HandlerError(e)))) => Err(e),
        Err(_) => Err(ts_control::LogoutError::Stopped),
    }
}
forward!(
    PeerTracker,
    peer_tracker::PeerByName,
    peer_tracker::PeerByTailnetIp,
    peer_tracker::PeerByAcceptedRoute
);
