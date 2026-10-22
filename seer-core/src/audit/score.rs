//! Turns check runs and findings into category grades and an overall grade.
//!
//! Each category starts at 100 and loses [`Severity::deduction`] points per
//! finding (floor 0). A category with at least one check that ran is graded;
//! one whose checks were all incomplete is ungraded (`?`) and drops out of
//! the overall weighted mean, whose weights are renormalised. Caps apply
//! after the mean: any Critical caps the letter at F, otherwise any High at
//! C — a takeover or an expired certificate cannot hide behind good scores.

use serde::Serialize;

use super::finding::{Category, CheckRun, CheckStatus, Finding, Severity};
use crate::grade::Letter;

/// How a category came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CategoryState {
    Graded,
    /// Every check in the category was incomplete.
    Incomplete,
    /// No check applied.
    NotApplicable,
}

/// One category's grade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CategoryGrade {
    pub category: Category,
    pub state: CategoryState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub letter: Option<Letter>,
}

/// The overall grade after caps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OverallGrade {
    /// Weighted mean of the graded categories (caps do not change it).
    pub score: u32,
    pub letter: Letter,
    /// The severity whose cap lowered the letter, if one did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capped_by: Option<Severity>,
}

/// Grades every category in [`Category::ALL`] order.
pub(crate) fn grade_categories(runs: &[CheckRun], findings: &[Finding]) -> Vec<CategoryGrade> {
    Category::ALL
        .iter()
        .map(|&category| {
            let mut statuses = runs
                .iter()
                .filter(|r| r.category == category)
                .map(|r| &r.status);
            let state = if statuses.clone().any(|s| *s == CheckStatus::Ran) {
                CategoryState::Graded
            } else if statuses.any(|s| matches!(s, CheckStatus::Incomplete { .. })) {
                CategoryState::Incomplete
            } else {
                CategoryState::NotApplicable
            };
            let score = (state == CategoryState::Graded).then(|| {
                let lost: u32 = findings
                    .iter()
                    .filter(|f| f.category == category)
                    .map(|f| f.severity.deduction())
                    .sum();
                100u32.saturating_sub(lost)
            });
            CategoryGrade {
                category,
                state,
                score,
                letter: score.map(Letter::from_score),
            }
        })
        .collect()
}

/// The overall grade, or `None` when no category was graded.
pub(crate) fn overall(grades: &[CategoryGrade], findings: &[Finding]) -> Option<OverallGrade> {
    let graded: Vec<(u32, u32)> = grades
        .iter()
        .filter_map(|g| g.score.map(|s| (s, g.category.weight())))
        .collect();
    let total_weight: u32 = graded.iter().map(|(_, w)| w).sum();
    if total_weight == 0 {
        return None;
    }
    let score = graded.iter().map(|(s, w)| s * w).sum::<u32>() / total_weight;
    let uncapped = Letter::from_score(score);
    let worst = findings.iter().map(|f| f.severity).max();
    let cap = match worst {
        Some(Severity::Critical) => Some((Severity::Critical, Letter::F)),
        Some(Severity::High) => Some((Severity::High, Letter::C)),
        _ => None,
    };
    let (letter, capped_by) = match cap {
        Some((severity, ceiling)) if uncapped > ceiling => (ceiling, Some(severity)),
        _ => (uncapped, None),
    };
    Some(OverallGrade {
        score,
        letter,
        capped_by,
    })
}

/// The pass gate: a grade exists, nothing is Critical, and the letter meets
/// `fail_under` when one is set. An ungraded (e.g. offline) audit never passes.
pub(crate) fn passed(
    overall: Option<&OverallGrade>,
    findings: &[Finding],
    fail_under: Option<Letter>,
) -> bool {
    let Some(overall) = overall else {
        return false;
    };
    !findings.iter().any(|f| f.severity == Severity::Critical)
        && fail_under.is_none_or(|threshold| overall.letter >= threshold)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::finding::{Category, CheckRun, CheckStatus, Finding, Severity};

    fn ran(check: &'static str, category: Category) -> CheckRun {
        CheckRun {
            check,
            category,
            status: CheckStatus::Ran,
        }
    }
    fn incomplete(check: &'static str, category: Category) -> CheckRun {
        CheckRun {
            check,
            category,
            status: CheckStatus::Incomplete {
                reason: "timeout".into(),
            },
        }
    }
    fn na(check: &'static str, category: Category) -> CheckRun {
        CheckRun {
            check,
            category,
            status: CheckStatus::NotApplicable {
                reason: "n/a".into(),
            },
        }
    }
    fn finding(category: Category, severity: Severity) -> Finding {
        Finding::new("web.test.thing", category, severity, "example.com", "t")
    }
    fn grade_of(grades: &[CategoryGrade], c: Category) -> &CategoryGrade {
        grades.iter().find(|g| g.category == c).unwrap()
    }
    fn all_ran() -> Vec<CheckRun> {
        Category::ALL.iter().map(|&c| ran("x", c)).collect()
    }

    #[test]
    fn deductions_accumulate_and_floor_at_zero() {
        let findings = vec![
            finding(Category::Web, Severity::Medium),
            finding(Category::Web, Severity::Low),
        ];
        let grades = grade_categories(&all_ran(), &findings);
        assert_eq!(grade_of(&grades, Category::Web).score, Some(87));
        assert_eq!(grade_of(&grades, Category::Web).letter, Some(Letter::A));

        let findings = vec![
            finding(Category::Tls, Severity::Critical),
            finding(Category::Tls, Severity::Critical),
        ];
        let grades = grade_categories(&all_ran(), &findings);
        assert_eq!(grade_of(&grades, Category::Tls).score, Some(0));
    }

    #[test]
    fn categories_are_graded_incomplete_or_not_applicable() {
        let runs = vec![
            ran("a", Category::Email),
            incomplete("b", Category::Email),
            incomplete("c", Category::Dns),
            na("d", Category::Takeover),
        ];
        let grades = grade_categories(&runs, &[]);
        assert_eq!(grades.len(), 6);
        assert_eq!(
            grade_of(&grades, Category::Email).state,
            CategoryState::Graded
        );
        assert_eq!(
            grade_of(&grades, Category::Dns).state,
            CategoryState::Incomplete
        );
        assert_eq!(grade_of(&grades, Category::Dns).score, None);
        assert_eq!(
            grade_of(&grades, Category::Takeover).state,
            CategoryState::NotApplicable
        );
        // No run at all reads as not applicable, never as a pass.
        assert_eq!(
            grade_of(&grades, Category::Web).state,
            CategoryState::NotApplicable
        );
    }

    #[test]
    fn overall_is_the_weighted_mean_of_graded_categories() {
        // Web 70 (weight 20) + every other ran category 100.
        let findings = vec![
            finding(Category::Web, Severity::Medium),
            finding(Category::Web, Severity::Medium),
            finding(Category::Web, Severity::Medium),
        ];
        let grades = grade_categories(&all_ran(), &findings);
        let o = overall(&grades, &findings).unwrap();
        // (70*20 + 100*80) / 100 = 94
        assert_eq!(o.score, 94);
        assert_eq!(o.letter, Letter::A);
        assert_eq!(o.capped_by, None);
    }

    #[test]
    fn ungraded_categories_drop_out_and_weights_renormalise() {
        // Only Registration (weight 10) graded, at 90.
        let runs = vec![
            ran("r", Category::Registration),
            incomplete("e", Category::Email),
        ];
        let findings = vec![finding(Category::Registration, Severity::Medium)];
        let grades = grade_categories(&runs, &findings);
        assert_eq!(overall(&grades, &findings).unwrap().score, 90);
    }

    #[test]
    fn a_critical_caps_at_f_and_a_high_caps_at_c() {
        let crit = vec![finding(Category::Takeover, Severity::Critical)];
        let o = overall(&grade_categories(&all_ran(), &crit), &crit).unwrap();
        assert_eq!(o.letter, Letter::F);
        assert_eq!(o.capped_by, Some(Severity::Critical));

        let high = vec![finding(Category::Email, Severity::High)];
        let o = overall(&grade_categories(&all_ran(), &high), &high).unwrap();
        assert_eq!(o.letter, Letter::C);
        assert_eq!(o.capped_by, Some(Severity::High));
    }

    #[test]
    fn a_cap_that_does_not_lower_the_grade_is_not_reported() {
        // Score already below C: the High cap changes nothing.
        let findings: Vec<Finding> = Category::ALL
            .iter()
            .flat_map(|&c| [finding(c, Severity::High), finding(c, Severity::High)])
            .collect();
        let o = overall(&grade_categories(&all_ran(), &findings), &findings).unwrap();
        assert_eq!(o.score, 50);
        assert_eq!(o.letter, Letter::D);
        assert_eq!(o.capped_by, None);
    }

    #[test]
    fn nothing_graded_means_no_overall() {
        let runs = vec![incomplete("a", Category::Email)];
        assert_eq!(overall(&grade_categories(&runs, &[]), &[]), None);
    }

    #[test]
    fn passed_requires_a_grade() {
        assert!(!passed(None, &[], None));
    }

    #[test]
    fn passed_fails_on_critical_or_below_threshold() {
        let a = OverallGrade {
            score: 90,
            letter: Letter::A,
            capped_by: None,
        };
        assert!(passed(Some(&a), &[], None));
        assert!(passed(Some(&a), &[], Some(Letter::A)));
        assert!(!passed(Some(&a), &[], Some(Letter::APlus)));
        let crit = vec![finding(Category::Tls, Severity::Critical)];
        assert!(!passed(Some(&a), &crit, None));
    }
}
