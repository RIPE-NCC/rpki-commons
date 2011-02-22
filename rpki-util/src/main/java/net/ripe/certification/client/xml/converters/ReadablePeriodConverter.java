package net.ripe.certification.client.xml.converters;

import org.joda.time.ReadablePeriod;
import org.joda.time.format.ISOPeriodFormat;

import com.thoughtworks.xstream.converters.SingleValueConverter;

public class ReadablePeriodConverter implements SingleValueConverter {

	@SuppressWarnings("rawtypes")
	@Override
    public boolean canConvert(Class type) {
        return ReadablePeriod.class.isAssignableFrom(type);
    }

	@Override
    public Object fromString(String str) {
        return ISOPeriodFormat.standard().parsePeriod(str);
    }

	@Override
    public String toString(Object obj) {
        return ISOPeriodFormat.standard().print((ReadablePeriod) obj);
    }
}
