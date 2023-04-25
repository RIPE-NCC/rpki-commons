package net.ripe.rpki.commons.crypto.rfc3779;

import lombok.NonNull;
import lombok.Value;
import net.ripe.ipresource.ImmutableResourceSet;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import org.apache.commons.lang3.Validate;

import java.io.Serializable;
import java.util.*;
import java.util.function.UnaryOperator;

@Value
public class ResourceExtension implements Serializable {
    private static final ImmutableResourceSet[] RESOURCES_BY_TYPE;

    static {
        RESOURCES_BY_TYPE = new ImmutableResourceSet[IpResourceType.values().length];
        for (IpResourceType type : IpResourceType.values()) {
            RESOURCES_BY_TYPE[type.ordinal()] = ImmutableResourceSet.of(type.getMinimum().upTo(type.getMaximum()));
        }
    }

    @NonNull EnumSet<IpResourceType> inheritedResourceTypes;
    @NonNull ImmutableResourceSet resources;

    private ResourceExtension(@NonNull EnumSet<IpResourceType> inheritedResourceTypes, @NonNull ImmutableResourceSet resources) {
        Validate.isTrue(!inheritedResourceTypes.isEmpty() || !resources.isEmpty(), "empty resource extension");
        for (IpResourceType inheritedResourceType : inheritedResourceTypes) {
            if (resources.containsType(inheritedResourceType)) {
                throw new IllegalArgumentException("resources overlap with inherited resource type " + inheritedResourceType);
            }
        }

        this.inheritedResourceTypes = inheritedResourceTypes;
        this.resources = resources;
    }

    public EnumSet<IpResourceType> getInheritedResourceTypes() {
        return EnumSet.copyOf(inheritedResourceTypes);
    }

    public static ResourceExtension of(EnumSet<IpResourceType> inheritedResourceTypes, ImmutableResourceSet resources) {
        return new ResourceExtension(EnumSet.copyOf(inheritedResourceTypes), resources);
    }

    public static ResourceExtension ofResources(ImmutableResourceSet resources) {
        return new ResourceExtension(EnumSet.noneOf(IpResourceType.class), resources);
    }

    public static ResourceExtension ofInherited(EnumSet<IpResourceType> inheritedResourceTypes) {
        return new ResourceExtension(EnumSet.copyOf(inheritedResourceTypes), ImmutableResourceSet.empty());
    }

    public static ResourceExtension allInherited() {
        return new ResourceExtension(EnumSet.allOf(IpResourceType.class), ImmutableResourceSet.empty());
    }

    public ResourceExtension withInheritedResourceTypes(EnumSet<IpResourceType> inheritedResourceTypes) {
        return new ResourceExtension(EnumSet.copyOf(inheritedResourceTypes), this.resources);
    }

    public ResourceExtension withResources(ImmutableResourceSet resources) {
        return new ResourceExtension(this.inheritedResourceTypes, resources);
    }

    public Optional<ResourceExtension> mapResources(UnaryOperator<ImmutableResourceSet> mapper) {
        ImmutableResourceSet updatedResources = mapper.apply(this.resources);
        return this.inheritedResourceTypes.isEmpty() && updatedResources.isEmpty()
            ? Optional.empty()
            : Optional.of(new ResourceExtension(this.inheritedResourceTypes, updatedResources));
    }

    /**
     * Determines the effective resources based on the parent resources and this resource extensions inherited and
     * specified resources.
     *
     * @param parentResources parent certificate's resources
     * @return the effective resource set
     */
    public ImmutableResourceSet deriveResources(ImmutableResourceSet parentResources) {
        if (inheritedResourceTypes.isEmpty()) {
            return this.resources;
        }
        if (inheritedResourceTypes.containsAll(EnumSet.allOf(IpResourceType.class))) {
            return parentResources;
        }
        ImmutableResourceSet result = this.resources;
        for (IpResourceType type : inheritedResourceTypes) {
            result = result.union(parentResources.intersection(RESOURCES_BY_TYPE[type.ordinal()]));
        }
        return result;
    }

    public boolean isResourceTypesInherited(Collection<IpResourceType> resourceTypes) {
        return inheritedResourceTypes.containsAll(resourceTypes);
    }

    public boolean isResourceSetInherited() {
        return !inheritedResourceTypes.isEmpty();
    }

    public boolean containsResources(IpResourceSet that) {
        return resources.contains(that);
    }

    public boolean containsResources(ImmutableResourceSet that) {
        return resources.contains(that);
    }
}
