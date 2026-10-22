//! The A+…F letter scale shared by every graded report.
//!
//! `seer headers` and `seer audit` both turn a 0–100 score into a letter;
//! the bands live here once so the same letter means the same thing in both.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A letter grade, declared worst (`F`) to best (`APlus`) so `Ord` compares
/// grades directly (`min` caps a grade).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Letter {
    F,
    E,
    D,
    C,
    B,
    A,
    #[serde(rename = "A+")]
    APlus,
}

impl Letter {
    /// Maps a 0–100 score to its band.
    pub fn from_score(score: u32) -> Self {
        match score {
            95..=u32::MAX => Letter::APlus,
            85..=94 => Letter::A,
            75..=84 => Letter::B,
            65..=74 => Letter::C,
            50..=64 => Letter::D,
            30..=49 => Letter::E,
            _ => Letter::F,
        }
    }

    /// The printed letter (`"A+"` … `"F"`), identical to its serde form.
    pub fn as_str(self) -> &'static str {
        match self {
            Letter::APlus => "A+",
            Letter::A => "A",
            Letter::B => "B",
            Letter::C => "C",
            Letter::D => "D",
            Letter::E => "E",
            Letter::F => "F",
        }
    }
}

impl fmt::Display for Letter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Letter {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_uppercase().as_str() {
            "A+" => Ok(Letter::APlus),
            "A" => Ok(Letter::A),
            "B" => Ok(Letter::B),
            "C" => Ok(Letter::C),
            "D" => Ok(Letter::D),
            "E" => Ok(Letter::E),
            "F" => Ok(Letter::F),
            other => Err(format!(
                "invalid grade '{other}' (expected A+, A, B, C, D, E or F)"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_bands_match_the_header_audit_scale() {
        for (score, letter) in [
            (100, Letter::APlus),
            (95, Letter::APlus),
            (94, Letter::A),
            (85, Letter::A),
            (84, Letter::B),
            (75, Letter::B),
            (74, Letter::C),
            (65, Letter::C),
            (64, Letter::D),
            (50, Letter::D),
            (49, Letter::E),
            (30, Letter::E),
            (29, Letter::F),
            (0, Letter::F),
        ] {
            assert_eq!(Letter::from_score(score), letter, "score {score}");
        }
    }

    #[test]
    fn letters_order_worst_to_best() {
        assert!(Letter::F < Letter::E);
        assert!(Letter::C < Letter::B);
        assert!(Letter::A < Letter::APlus);
        assert_eq!(Letter::APlus.min(Letter::C), Letter::C);
    }

    #[test]
    fn parses_and_prints_round_trip() {
        for letter in [
            Letter::F,
            Letter::E,
            Letter::D,
            Letter::C,
            Letter::B,
            Letter::A,
            Letter::APlus,
        ] {
            assert_eq!(letter.as_str().parse::<Letter>(), Ok(letter));
            assert_eq!(letter.to_string(), letter.as_str());
        }
        assert_eq!(" a+ ".parse::<Letter>(), Ok(Letter::APlus));
        assert!("Z".parse::<Letter>().is_err());
    }

    #[test]
    fn serializes_as_the_printed_letter() {
        assert_eq!(serde_json::to_string(&Letter::APlus).unwrap(), "\"A+\"");
        assert_eq!(serde_json::to_string(&Letter::C).unwrap(), "\"C\"");
    }
}
