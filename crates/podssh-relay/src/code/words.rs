//! The words of a code: the PGP word list (Juola and Zimmermann), as
//! magic-wormhole's `src/wormhole/_wordlist.py` holds it, in lower case. A
//! byte gives an even word (two syllables) and an odd one (three); a code
//! alternates them, odd first, as magic-wormhole's `choose_words` does, so
//! that a dropped word or two swapped ones is seen. 256 of each and none in
//! both, so each word is 8 bits.

/// The even words, by byte.
#[rustfmt::skip]
pub const EVEN: [&str; 256] = [
    "aardvark", "absurd", "accrue", "acme", "adrift", "adult", "afflict", "ahead", "aimless", "algol", "allow",
    "alone", "ammo", "ancient", "apple", "artist", "assume", "athens", "atlas", "aztec", "baboon", "backfield",
    "backward", "banjo", "beaming", "bedlamp", "beehive", "beeswax", "befriend", "belfast", "berserk", "billiard",
    "bison", "blackjack", "blockade", "blowtorch", "bluebird", "bombast", "bookshelf", "brackish", "breadline",
    "breakup", "brickyard", "briefcase", "burbank", "button", "buzzard", "cement", "chairlift", "chatter", "checkup",
    "chisel", "choking", "chopper", "christmas", "clamshell", "classic", "classroom", "cleanup", "clockwork", "cobra",
    "commence", "concert", "cowbell", "crackdown", "cranky", "crowfoot", "crucial", "crumpled", "crusade", "cubic",
    "dashboard", "deadbolt", "deckhand", "dogsled", "dragnet", "drainage", "dreadful", "drifter", "dropper",
    "drumbeat", "drunken", "dupont", "dwelling", "eating", "edict", "egghead", "eightball", "endorse", "endow",
    "enlist", "erase", "escape", "exceed", "eyeglass", "eyetooth", "facial", "fallout", "flagpole", "flatfoot",
    "flytrap", "fracture", "framework", "freedom", "frighten", "gazelle", "geiger", "glitter", "glucose", "goggles",
    "goldfish", "gremlin", "guidance", "hamlet", "highchair", "hockey", "indoors", "indulge", "inverse", "involve",
    "island", "jawbone", "keyboard", "kickoff", "kiwi", "klaxon", "locale", "lockup", "merit", "minnow", "miser",
    "mohawk", "mural", "music", "necklace", "neptune", "newborn", "nightbird", "oakland", "obtuse", "offload",
    "optic", "orca", "payday", "peachy", "pheasant", "physique", "playhouse", "pluto", "preclude", "prefer",
    "preshrunk", "printer", "prowler", "pupil", "puppy", "python", "quadrant", "quiver", "quota", "ragtime",
    "ratchet", "rebirth", "reform", "regain", "reindeer", "rematch", "repay", "retouch", "revenge", "reward",
    "rhythm", "ribcage", "ringbolt", "robust", "rocker", "ruffled", "sailboat", "sawdust", "scallion", "scenic",
    "scorecard", "scotland", "seabird", "select", "sentence", "shadow", "shamrock", "showgirl", "skullcap", "skydive",
    "slingshot", "slowdown", "snapline", "snapshot", "snowcap", "snowslide", "solo", "southward", "soybean",
    "spaniel", "spearhead", "spellbind", "spheroid", "spigot", "spindle", "spyglass", "stagehand", "stagnate",
    "stairway", "standard", "stapler", "steamship", "sterling", "stockman", "stopwatch", "stormy", "sugar",
    "surmount", "suspense", "sweatband", "swelter", "tactics", "talon", "tapeworm", "tempest", "tiger", "tissue",
    "tonic", "topmost", "tracker", "transit", "trauma", "treadmill", "trojan", "trouble", "tumor", "tunnel", "tycoon",
    "uncut", "unearth", "unwind", "uproot", "upset", "upshot", "vapor", "village", "virus", "vulcan", "waffle",
    "wallet", "watchword", "wayside", "willow", "woodlark", "zulu",
];

/// The odd words, by byte.
#[rustfmt::skip]
pub const ODD: [&str; 256] = [
    "adroitness", "adviser", "aftermath", "aggregate", "alkali", "almighty", "amulet", "amusement", "antenna",
    "applicant", "apollo", "armistice", "article", "asteroid", "atlantic", "atmosphere", "autopsy", "babylon",
    "backwater", "barbecue", "belowground", "bifocals", "bodyguard", "bookseller", "borderline", "bottomless",
    "bradbury", "bravado", "brazilian", "breakaway", "burlington", "businessman", "butterfat", "camelot", "candidate",
    "cannonball", "capricorn", "caravan", "caretaker", "celebrate", "cellulose", "certify", "chambermaid", "cherokee",
    "chicago", "clergyman", "coherence", "combustion", "commando", "company", "component", "concurrent", "confidence",
    "conformist", "congregate", "consensus", "consulting", "corporate", "corrosion", "councilman", "crossover",
    "crucifix", "cumbersome", "customer", "dakota", "decadence", "december", "decimal", "designing", "detector",
    "detergent", "determine", "dictator", "dinosaur", "direction", "disable", "disbelief", "disruptive", "distortion",
    "document", "embezzle", "enchanting", "enrollment", "enterprise", "equation", "equipment", "escapade", "eskimo",
    "everyday", "examine", "existence", "exodus", "fascinate", "filament", "finicky", "forever", "fortitude",
    "frequency", "gadgetry", "galveston", "getaway", "glossary", "gossamer", "graduate", "gravity", "guitarist",
    "hamburger", "hamilton", "handiwork", "hazardous", "headwaters", "hemisphere", "hesitate", "hideaway", "holiness",
    "hurricane", "hydraulic", "impartial", "impetus", "inception", "indigo", "inertia", "infancy", "inferno",
    "informant", "insincere", "insurgent", "integrate", "intention", "inventive", "istanbul", "jamaica", "jupiter",
    "leprosy", "letterhead", "liberty", "maritime", "matchmaker", "maverick", "medusa", "megaton", "microscope",
    "microwave", "midsummer", "millionaire", "miracle", "misnomer", "molasses", "molecule", "montana", "monument",
    "mosquito", "narrative", "nebula", "newsletter", "norwegian", "october", "ohio", "onlooker", "opulent", "orlando",
    "outfielder", "pacific", "pandemic", "pandora", "paperweight", "paragon", "paragraph", "paramount", "passenger",
    "pedigree", "pegasus", "penetrate", "perceptive", "performance", "pharmacy", "phonetic", "photograph", "pioneer",
    "pocketful", "politeness", "positive", "potato", "processor", "provincial", "proximate", "puberty", "publisher",
    "pyramid", "quantity", "racketeer", "rebellion", "recipe", "recover", "repellent", "replica", "reproduce",
    "resistor", "responsive", "retraction", "retrieval", "retrospect", "revenue", "revival", "revolver", "sandalwood",
    "sardonic", "saturday", "savagery", "scavenger", "sensation", "sociable", "souvenir", "specialist", "speculate",
    "stethoscope", "stupendous", "supportive", "surrender", "suspicious", "sympathy", "tambourine", "telephone",
    "therapist", "tobacco", "tolerance", "tomorrow", "torpedo", "tradition", "travesty", "trombonist", "truncated",
    "typewriter", "ultimate", "undaunted", "underfoot", "unicorn", "unify", "universe", "unravel", "upcoming",
    "vacancy", "vagabond", "vertigo", "virginia", "visitor", "vocalist", "voyager", "warranty", "waterloo",
    "whimsical", "wichita", "wilmington", "wyoming", "yesteryear", "yucatan",
];

/// The list of the `at`th word of a code, from 0: odd words first.
pub fn list(at: usize) -> &'static [&'static str; 256] {
    if at.is_multiple_of(2) {
        &ODD
    } else {
        &EVEN
    }
}

/// The `at`th word of a code for `byte`.
pub fn word(at: usize, byte: u8) -> &'static str {
    list(at)[usize::from(byte)]
}

/// The word of the `at`th place's list that `typed` is, in any case.
pub fn find(at: usize, typed: &str) -> Option<&'static str> {
    let lower = typed.to_ascii_lowercase();
    list(at).iter().copied().find(|w| *w == lower)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_list_has_256_words_of_its_own_in_magic_wormholes_order() {
        for list in [&EVEN, &ODD] {
            let mut seen = std::collections::HashSet::new();
            for w in list.iter() {
                assert!(!w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase()), "{w:?}");
                assert!(seen.insert(*w), "{w} is twice in its list");
            }
        }
        assert!(EVEN.iter().all(|w| !ODD.contains(w)), "no word is in both lists");
        // The ends of `raw_words` in `_wordlist.py`: '00' and 'FF'.
        assert_eq!((EVEN[0], ODD[0]), ("aardvark", "adroitness"));
        assert_eq!((EVEN[255], ODD[255]), ("zulu", "yucatan"));
        assert_eq!((EVEN[0x0a], ODD[0x0a]), ("allow", "apollo"));
    }

    #[test]
    fn a_code_alternates_the_lists_odd_first_and_a_word_is_found_in_any_case() {
        assert_eq!(word(0, 0), "adroitness");
        assert_eq!(word(1, 0), "aardvark");
        assert_eq!(word(2, 0xff), "yucatan");
        assert_eq!(find(0, "CrossOver"), Some("crossover"));
        assert_eq!(find(1, "crossover"), None, "an odd word in an even place");
        assert_eq!(find(1, "clockwork"), Some("clockwork"));
        assert_eq!(find(0, "nonsense"), None);
    }
}
