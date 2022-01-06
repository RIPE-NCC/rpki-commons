package net.ripe.rpki.commons.util;

public final class Specifications {

    private Specifications() {
    }

    public static <T> Specification<T> alwaysTrue() {
        return new AlwaysTrueSpecification<>();
    }

    public static <T> Specification<T> alwaysFalse() {
        return new AlwaysFalseSpecification<>();
    }

    private static final class AlwaysFalseSpecification<T> implements Specification<T> {
        @Override
        public boolean isSatisfiedBy(T candidate) {
            return false;
        }

        @Override
        public int hashCode() {
            return Boolean.FALSE.hashCode();
        }

        @Override
        public boolean equals(Object obj) {
            return (this == obj) || (obj instanceof AlwaysFalseSpecification);
        }
    }

    private static final class AlwaysTrueSpecification<T> implements Specification<T> {
        @Override
        public boolean isSatisfiedBy(T candidate) {
            return true;
        }

        @Override
        public int hashCode() {
            return Boolean.TRUE.hashCode();
        }

        @Override
        public boolean equals(Object obj) {
            return (this == obj) || (obj instanceof AlwaysTrueSpecification);
        }
    }
}
