package net.ripe.rpki.commons.xml.converters;

import com.thoughtworks.xstream.converters.SingleValueConverter;

import javax.security.auth.x500.X500Principal;

public class X500PrincipalConverter implements SingleValueConverter {

    @Override
    public boolean canConvert(Class type) {
        return X500Principal.class.equals(type);
    }

    @Override
    public Object fromString(String s) {
        return new X500Principal(s);
    }

    @Override
    public String toString(Object principal) {
        return ((X500Principal) principal).getName();
    }
}
