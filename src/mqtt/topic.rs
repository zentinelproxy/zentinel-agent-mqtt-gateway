//! MQTT topic matching with wildcards
//!
//! Implements MQTT topic filter matching per the MQTT 3.1.1 and 5.0 specifications.
//! Supports single-level (+) and multi-level (#) wildcards.

/// Topic matcher for MQTT topic filters
#[derive(Debug, Clone)]
pub struct TopicMatcher;

impl TopicMatcher {
    /// Create a new topic matcher
    pub fn new() -> Self {
        Self
    }

    /// Check if a topic matches a topic filter
    ///
    /// # Arguments
    /// * `topic` - The actual topic name (no wildcards allowed)
    /// * `filter` - The topic filter pattern (may contain + and # wildcards)
    ///
    /// # MQTT Wildcard Rules
    /// * `+` matches exactly one topic level
    /// * `#` matches zero or more topic levels (must be last character)
    /// * Wildcards can only appear after a `/` separator (except at start)
    ///
    /// # Examples
    /// ```
    /// use sentinel_agent_mqtt_gateway::mqtt::TopicMatcher;
    ///
    /// let matcher = TopicMatcher::new();
    /// assert!(matcher.matches("sensors/temp/living-room", "sensors/+/living-room"));
    /// assert!(matcher.matches("sensors/temp/living-room", "sensors/#"));
    /// assert!(!matcher.matches("sensors/temp/bedroom", "sensors/+/living-room"));
    /// ```
    pub fn matches(&self, topic: &str, filter: &str) -> bool {
        // Split into levels
        let topic_levels: Vec<&str> = topic.split('/').collect();
        let filter_levels: Vec<&str> = filter.split('/').collect();

        self.match_levels(&topic_levels, &filter_levels)
    }

    fn match_levels(&self, topic: &[&str], filter: &[&str]) -> bool {
        let mut t_idx = 0;
        let mut f_idx = 0;

        while f_idx < filter.len() {
            let f_level = filter[f_idx];

            match f_level {
                "#" => {
                    // # matches everything remaining (must be last in filter)
                    return f_idx == filter.len() - 1;
                }
                "+" => {
                    // + matches exactly one level
                    if t_idx >= topic.len() {
                        return false;
                    }
                    t_idx += 1;
                    f_idx += 1;
                }
                _ => {
                    // Exact match required
                    if t_idx >= topic.len() || topic[t_idx] != f_level {
                        return false;
                    }
                    t_idx += 1;
                    f_idx += 1;
                }
            }
        }

        // Both must be fully consumed for a match
        t_idx == topic.len()
    }

    /// Check if a topic filter is valid
    ///
    /// # Rules
    /// * `#` must be the last character and preceded by `/` (or be the only character)
    /// * `+` must be the entire level (surrounded by `/` or at start/end)
    /// * Empty levels are not allowed (no `//`)
    pub fn is_valid_filter(&self, filter: &str) -> bool {
        if filter.is_empty() {
            return false;
        }

        let levels: Vec<&str> = filter.split('/').collect();

        for (i, level) in levels.iter().enumerate() {
            // Empty levels not allowed
            if level.is_empty() {
                return false;
            }

            // # must be last level and alone
            if level.contains('#') && (*level != "#" || i != levels.len() - 1) {
                return false;
            }

            // + must be alone in its level
            if level.contains('+') && *level != "+" {
                return false;
            }
        }

        true
    }

    /// Check if a topic name is valid (no wildcards allowed)
    pub fn is_valid_topic(&self, topic: &str) -> bool {
        if topic.is_empty() {
            return false;
        }

        // Topics starting with $ are reserved (system topics)
        // We allow them but they shouldn't match wildcards starting with +/#

        // No wildcards allowed in topic names
        if topic.contains('+') || topic.contains('#') {
            return false;
        }

        // No empty levels
        !topic.split('/').any(|level| level.is_empty())
    }

    /// Check if a topic is a system topic (starts with $)
    pub fn is_system_topic(&self, topic: &str) -> bool {
        topic.starts_with('$')
    }
}

impl Default for TopicMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let matcher = TopicMatcher::new();
        assert!(matcher.matches("sensors/temp", "sensors/temp"));
        assert!(!matcher.matches("sensors/temp", "sensors/humidity"));
    }

    #[test]
    fn test_single_level_wildcard() {
        let matcher = TopicMatcher::new();

        // + matches one level
        assert!(matcher.matches("sensors/temp", "sensors/+"));
        assert!(matcher.matches("sensors/temp/living", "+/temp/living"));
        assert!(matcher.matches("a/b/c", "a/+/c"));

        // + requires exactly one level
        assert!(!matcher.matches("sensors", "sensors/+"));
        assert!(!matcher.matches("sensors/temp/extra", "sensors/+"));
    }

    #[test]
    fn test_multi_level_wildcard() {
        let matcher = TopicMatcher::new();

        // # matches zero or more levels
        assert!(matcher.matches("sensors", "sensors/#"));
        assert!(matcher.matches("sensors/temp", "sensors/#"));
        assert!(matcher.matches("sensors/temp/living", "sensors/#"));
        assert!(matcher.matches("sensors/temp/living/zone1", "sensors/#"));

        // # must be at the end
        assert!(matcher.matches("anything", "#"));
        assert!(matcher.matches("a/b/c/d", "#"));
    }

    #[test]
    fn test_combined_wildcards() {
        let matcher = TopicMatcher::new();

        assert!(matcher.matches("a/b/c/d", "+/+/+/+"));
        assert!(matcher.matches("a/b/c/d", "+/b/+/d"));
        assert!(matcher.matches("a/b/c/d", "+/#"));
        assert!(matcher.matches("a/b/c/d", "a/+/#"));
    }

    #[test]
    fn test_system_topics() {
        let matcher = TopicMatcher::new();

        // System topics start with $
        assert!(matcher.is_system_topic("$SYS/broker/clients"));
        assert!(!matcher.is_system_topic("sensors/temp"));

        // Wildcards don't match system topics at first level (per MQTT spec recommendation)
        // This is a policy decision, actual matching still works
        assert!(matcher.matches("$SYS/broker", "$SYS/+"));
    }

    #[test]
    fn test_valid_filters() {
        let matcher = TopicMatcher::new();

        assert!(matcher.is_valid_filter("sensors/temp"));
        assert!(matcher.is_valid_filter("sensors/+"));
        assert!(matcher.is_valid_filter("sensors/#"));
        assert!(matcher.is_valid_filter("+/temp"));
        assert!(matcher.is_valid_filter("#"));
        assert!(matcher.is_valid_filter("+"));

        // Invalid filters
        assert!(!matcher.is_valid_filter("")); // Empty
        assert!(!matcher.is_valid_filter("sensors//temp")); // Empty level
        assert!(!matcher.is_valid_filter("sensors/temp+1")); // + not alone
        assert!(!matcher.is_valid_filter("sensors/#/temp")); // # not at end
        assert!(!matcher.is_valid_filter("sensors/temp#")); // # not alone
    }

    #[test]
    fn test_valid_topics() {
        let matcher = TopicMatcher::new();

        assert!(matcher.is_valid_topic("sensors/temp"));
        assert!(matcher.is_valid_topic("$SYS/broker/clients"));

        // Invalid topics (contain wildcards)
        assert!(!matcher.is_valid_topic("sensors/+"));
        assert!(!matcher.is_valid_topic("sensors/#"));
        assert!(!matcher.is_valid_topic("")); // Empty
        assert!(!matcher.is_valid_topic("sensors//temp")); // Empty level
    }
}
