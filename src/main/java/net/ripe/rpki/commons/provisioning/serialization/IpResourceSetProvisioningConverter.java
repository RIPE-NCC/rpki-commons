package net.ripe.rpki.commons.provisioning.serialization;

import com.thoughtworks.xstream.converters.basic.AbstractSingleValueConverter;
import net.ripe.ipresource.IpResourceSet;


public class IpResourceSetProvisioningConverter extends AbstractSingleValueConverter {

    public static final IpResourceSetProvisioningConverter INSTANCE = new IpResourceSetProvisioningConverter();

    @Override
    public boolean canConvert(@SuppressWarnings("rawtypes") Class type) {
        return type == IpResourceSet.class;
    }

    @Override
    public IpResourceSet fromString(String str) {
        return IpResourceSet.parse(str);
    }

    @Override
    public String toString(Object obj) {
        if (obj == null) {
            return null;
        }
        return obj.toString().replace(" ", "").replace("AS", "");
    }
}
