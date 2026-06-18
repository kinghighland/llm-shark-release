use license_core::PlanTier;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyInput {
    pub plan_tier: PlanTier,
    pub topn_limit: i32,
    pub daily_analysis_limit: i32,
    pub used_today: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePolicy {
    pub topn: i32,
    pub daily_limit: i32,
    pub remaining_today: i32,
    pub unlimited: bool,
    pub can_analyze_now: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyError {
    InvalidTopn,
    InvalidDailyLimit,
}

pub fn build_runtime_policy(input: PolicyInput) -> Result<RuntimePolicy, PolicyError> {
    let expected_topn = match input.plan_tier {
        PlanTier::Free => 2,
        PlanTier::Monthly => 5,
        PlanTier::Yearly => 10,
    };

    if input.topn_limit != expected_topn {
        return Err(PolicyError::InvalidTopn);
    }

    if !matches!(input.daily_analysis_limit, 3 | 10 | -1) {
        return Err(PolicyError::InvalidDailyLimit);
    }

    if input.daily_analysis_limit == -1 {
        return Ok(RuntimePolicy {
            topn: input.topn_limit,
            daily_limit: -1,
            remaining_today: -1,
            unlimited: true,
            can_analyze_now: true,
        });
    }

    let remaining = (input.daily_analysis_limit - input.used_today).max(0);
    Ok(RuntimePolicy {
        topn: input.topn_limit,
        daily_limit: input.daily_analysis_limit,
        remaining_today: remaining,
        unlimited: false,
        can_analyze_now: remaining > 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_free_policy() {
        let policy = build_runtime_policy(PolicyInput {
            plan_tier: PlanTier::Free,
            topn_limit: 2,
            daily_analysis_limit: 3,
            used_today: 1,
        })
        .expect("policy");

        assert_eq!(policy.topn, 2);
        assert_eq!(policy.remaining_today, 2);
        assert!(!policy.unlimited);
    }

    #[test]
    fn supports_unlimited_daily_limit() {
        let policy = build_runtime_policy(PolicyInput {
            plan_tier: PlanTier::Yearly,
            topn_limit: 10,
            daily_analysis_limit: -1,
            used_today: 99,
        })
        .expect("policy");

        assert!(policy.unlimited);
        assert_eq!(policy.remaining_today, -1);
        assert!(policy.can_analyze_now);
    }

    #[test]
    fn rejects_invalid_topn_mapping() {
        let result = build_runtime_policy(PolicyInput {
            plan_tier: PlanTier::Monthly,
            topn_limit: 10,
            daily_analysis_limit: 10,
            used_today: 0,
        });
        assert_eq!(result.expect_err("error"), PolicyError::InvalidTopn);
    }

    #[test]
    fn marks_limit_exhausted() {
        let policy = build_runtime_policy(PolicyInput {
            plan_tier: PlanTier::Monthly,
            topn_limit: 5,
            daily_analysis_limit: 10,
            used_today: 10,
        })
        .expect("policy");

        assert_eq!(policy.remaining_today, 0);
        assert!(!policy.can_analyze_now);
    }
}
