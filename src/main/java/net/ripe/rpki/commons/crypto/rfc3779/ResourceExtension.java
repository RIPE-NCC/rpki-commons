package net.ripe.rpki.commons.crypto.rfc3779;

import lombok.NonNull;
import lombok.Value;
import net.ripe.ipresource.ImmutableResourceSet;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import org.apache.commons.lang3.Validate;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;
import java.util.function.UnaryOperator;

@Value
public class ResourceExtension implements Serializable {
    @NonNull Set<IpResourceType> inheritedResourceTypes;
    @NonNull ImmutableResourceSet resources;

    private ResourceExtension(@NonNull Set<IpResourceType> inheritedResourceTypes, @NonNull ImmutableResourceSet resources) {
        Validate.isTrue(!inheritedResourceTypes.isEmpty() || !resources.isEmpty(), "empty resource extension");
        for (IpResourceType inheritedResourceType : inheritedResourceTypes) {
            if (resources.containsType(inheritedResourceType)) {
                throw new IllegalArgumentException("resources overlap with inherited resource type " + inheritedResourceType);
            }
        }

        this.inheritedResourceTypes = inheritedResourceTypes;
        this.resources = resources;
    }

    public static ResourceExtension of(Collection<IpResourceType> inheritedResourceTypes, ImmutableResourceSet resources) {
        return new ResourceExtension(Collections.unmodifiableSet(EnumSet.copyOf(inheritedResourceTypes)), resources);
    }

    public static ResourceExtension ofResources(ImmutableResourceSet resources) {
        return new ResourceExtension(Collections.unmodifiableSet(EnumSet.noneOf(IpResourceType.class)), resources);
    }

    public static ResourceExtension ofInherited(Collection<IpResourceType> inheritedResourceTypes) {
        return new ResourceExtension(Collections.unmodifiableSet(EnumSet.copyOf(inheritedResourceTypes)), ImmutableResourceSet.empty());
    }

    public static ResourceExtension allInherited() {
        return new ResourceExtension(Collections.unmodifiableSet(EnumSet.allOf(IpResourceType.class)), ImmutableResourceSet.empty());
    }

    public ResourceExtension withInheritedResourceTypes(Collection<IpResourceType> inheritedResourceTypes) {
        return new ResourceExtension(Collections.unmodifiableSet(EnumSet.copyOf(inheritedResourceTypes)), this.resources);
    }

    public ResourceExtension withResources(ImmutableResourceSet resources) {
        return new ResourceExtension(this.inheritedResourceTypes, resources);
    }

    public ResourceExtension mapResources(UnaryOperator<ImmutableResourceSet> mapper) {
        return new ResourceExtension(this.inheritedResourceTypes, mapper.apply(this.resources));
    }

    public ImmutableResourceSet deriveResources(ImmutableResourceSet parentResources) {
        if (inheritedResourceTypes.isEmpty()) {
            return this.resources;
        }
        if (inheritedResourceTypes.containsAll(EnumSet.allOf(IpResourceType.class))) {
            return parentResources;
        }
        ImmutableResourceSet result = this.resources;
        for (IpResourceType type : inheritedResourceTypes) {
            result = result.union(parentResources.intersection(ImmutableResourceSet.of(type.getMinimum().upTo(type.getMaximum()))));
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
}
