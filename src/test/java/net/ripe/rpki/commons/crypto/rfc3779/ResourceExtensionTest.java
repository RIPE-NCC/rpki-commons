package net.ripe.rpki.commons.crypto.rfc3779;


import net.ripe.ipresource.ImmutableResourceSet;
import net.ripe.ipresource.IpResourceType;
import org.junit.Test;

import java.util.EnumSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class ResourceExtensionTest {

    @Test
    public void should_enforce_non_empty_resource_extension() {
        assertThatThrownBy(() -> ResourceExtension.ofResources(ImmutableResourceSet.empty())).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ResourceExtension.ofInherited(EnumSet.noneOf(IpResourceType.class))).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void mapResources() {
        assertThat(
            ResourceExtension.ofResources(ImmutableResourceSet.ALL_PRIVATE_USE_RESOURCES)
                .mapResources(ignored -> ImmutableResourceSet.empty())
        ).isEmpty();
        assertThat(
            ResourceExtension.allInherited().mapResources(ignored -> ImmutableResourceSet.empty())
        ).hasValueSatisfying(re -> {
            assertThat(re.getInheritedResourceTypes()).containsExactly(IpResourceType.values());
            assertThat(re.getResources()).isEqualTo(ImmutableResourceSet.empty());
        });
        assertThat(
            ResourceExtension.ofResources(ImmutableResourceSet.ALL_PRIVATE_USE_RESOURCES)
                .mapResources(r -> r.intersection(ImmutableResourceSet.parse("192.0.0.0/8")))
        ).hasValueSatisfying(re -> {
            assertThat(re.getResources()).isEqualTo(ImmutableResourceSet.parse("192.168.0.0/16"));
            assertThat(re.isResourceSetInherited()).isFalse();
        });
    }
}
