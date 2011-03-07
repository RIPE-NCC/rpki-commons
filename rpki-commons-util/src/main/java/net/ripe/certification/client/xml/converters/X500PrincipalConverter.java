package net.ripe.certification.client.xml.converters;

import javax.security.auth.x500.X500Principal;

import com.thoughtworks.xstream.converters.SingleValueConverter;

public class X500PrincipalConverter implements SingleValueConverter {

	@SuppressWarnings("rawtypes")
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