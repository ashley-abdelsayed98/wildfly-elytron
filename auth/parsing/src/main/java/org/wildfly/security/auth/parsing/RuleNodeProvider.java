package org.wildfly.security.auth.parsing;

import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.auth.client.RuleNode;

class RuleNodeProvider<T> extends RuleNode {

    RuleNodeProvider(final RuleNode<T> next, final MatchRule rule, final T configuration) {
        super(next, rule, configuration);
    }


    protected T getConfiguration() {
        return (T) super.getConfiguration();
    }


}
