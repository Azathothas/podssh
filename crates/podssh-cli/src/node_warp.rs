//! The quick tunnel's node inside WARP's tunnel (T-374): where the cage's
//! proxy allows ports 443, 80 and 8443 alone, the edge's TCP port 7844 is
//! reached as any target of WARP's road (T-352). The tunnel is opened once,
//! with the device of `warp://` (its record in the cache, or a registration
//! once the user accepted the Terms), and kept for the node's next
//! connections to the edge while it lasts. In a build without the feature
//! `warp`, the road answers with what such a build would do.

use podssh_relay::quick::edge;

use crate::ssh::transport::Duplex;

/// The road's words, as the node says how it registered.
pub const ROAD: &str = "HTTP/2 inside WARP's tunnel";

/// The node's road to the edge inside WARP's tunnel.
pub(crate) struct WarpRoad {
    /// The user asked for it before the edge's other roads (`--warp`).
    pub first: bool,
    #[cfg(feature = "warp")]
    warp: Option<podssh_warp::Warp>,
}

impl WarpRoad {
    pub fn new(first: bool) -> WarpRoad {
        WarpRoad {
            first,
            #[cfg(feature = "warp")]
            warp: None,
        }
    }

    /// A TLS connection to `found` inside the tunnel, which opens first when
    /// it is not open; `say` tells of its opening. `say` is `Sync`, as the
    /// node's race runs each road in a task of its own (T-400).
    #[cfg(feature = "warp")]
    pub async fn edge(&mut self, found: &edge::Edge, say: &(dyn Fn(String) + Sync)) -> Result<Box<dyn Duplex>, String> {
        if self.warp.as_ref().is_some_and(|warp| warp.ended().is_some()) {
            self.warp = None;
        }
        if self.warp.is_none() {
            use crate::ssh::cloud::warp::road;
            let trust = crate::pairs::trust(None);
            let told = |line: &str| podssh_ssh::err_line!("podssh node: {line}");
            let mut device = road::device(&trust, &told, &|_: &str| {})
                .await
                .map_err(|(line, _)| format!("WARP's tunnel: {line}"))?;
            // A new key of the endpoint, which WARP's API gives, is kept in
            // the device's record (T-399).
            let opened = road::tunnel(&mut device, &trust, &|_: &str| {}).await;
            let warp = opened.map_err(|f| format!("WARP's tunnel: {f}"))?;
            say(format!("WARP's tunnel opened, to {}", warp.via()));
            self.warp = Some(warp);
        }
        let Some(warp) = self.warp.as_ref() else { return Err("WARP's tunnel did not open".into()) };
        let tls = podssh_relay::quick::edge_warp::connect(warp, found, &edge::trust()?).await?;
        Ok(Box::new(tls))
    }

    /// In a build without the feature, the road is not there, and says so.
    #[cfg(not(feature = "warp"))]
    pub async fn edge(
        &mut self,
        _found: &edge::Edge,
        _say: &(dyn Fn(String) + Sync),
    ) -> Result<Box<dyn Duplex>, String> {
        Err("a build with the feature warp reaches the edge inside WARP's tunnel too".into())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_road_s_words_are_the_library_s() {
        #[cfg(feature = "warp")]
        assert_eq!(super::ROAD, podssh_relay::quick::edge_warp::ROAD);
        assert!(super::ROAD.contains("WARP"));
    }

    /// A build without the feature says what one with it would do, and
    /// opens nothing.
    #[cfg(not(feature = "warp"))]
    #[tokio::test]
    async fn a_build_without_the_feature_names_it() {
        let found = podssh_relay::quick::edge::Edge::fixed("a test".into());
        let mut road = super::WarpRoad::new(false);
        let why = road.edge(&found, &|_| {}).await.err().unwrap();
        assert!(why.contains("the feature warp"), "{why}");
    }
}
