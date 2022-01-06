package net.ripe.rpki.commons.util;

/**
 * A DDD <a href="http://en.wikipedia.org/wiki/Specification_pattern">specification</a>
 */
public interface Specification<T> {

    /**
     * @param candidate the candidate to test.
     * @return true if the candidate satisfies this specification.
     */
    boolean isSatisfiedBy(T candidate);

}
