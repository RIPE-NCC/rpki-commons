package net.ripe.certification.csv;

/**
 * @author thies (thies@te-con.nl)
 *         Date: 1/26/11 11:53 AM
 */

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

import net.ripe.certification.csv.CsvFormatter.CsvColumn;

import org.junit.Before;
import org.junit.Test;

public class CsvFormatterTest {

    private CsvFormatter subject;
    private List<CsvColumn> columns;

    @Before
    public void setUp() {
        subject = new CsvFormatter();
        columns = new ArrayList<CsvColumn>();
        subject.setColumnList(columns);
    }

    @Test
    public void shouldAllowAddingAColumn() {
        String heading = "heading1";
        subject.addColumn(heading);
        assertEquals(1, columns.size());
    }

    @Test
    public void shouldAcceptLinesHappyFlow() {
        String heading = "heading1";
        subject.addColumn(heading);

        String val1 = "some text";
        subject.addLine(val1);
    }


    @Test(expected = IllegalArgumentException.class)
    public void shouldRejectLinesWithWrongNumberOfElements() {
        String heading = "heading1";
        subject.addColumn(heading);

        String val1 = "some text";
        subject.addLine(val1, val1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRejectLinesWhenSeperatorIsUsedInUnquotedField() {
        subject.addColumn("heading1");

        String val = "offending , in text";
        subject.addLine(val);
    }

    @Test
    public void shouldPrintLinesAndQuoteProperly() throws IOException {
        subject.addColumn("heading1");
        subject.addQuotedColumn("heading2");

        String val1 = "some text";
        String val2 = "more stuff";
        subject.addLine(val1, val2);

        StringWriter writer = new StringWriter();
        subject.printWithoutHeaders(writer);

        assertEquals("some text,\"more stuff\"\n", writer.toString());
    }

    @Test
    public void shouldUseEmptyStringForNullValues() throws IOException {
        subject.addColumn("heading1");
        subject.addColumn("heading2");

        String val1 = null;
        subject.addLine(val1, val1);

        StringWriter writer = new StringWriter();
        subject.printWithoutHeaders(writer);

        assertEquals(",\n", writer.toString());
    }


    @Test
    public void shouldPrintHeader() throws IOException {
        subject.addColumn("heading1");
        subject.addQuotedColumn("heading2");

        String val1 = "some text";
        String val2 = "more stuff";
        subject.addLine(val1, val2);

        StringWriter writer = new StringWriter();
        subject.printWithHeaders(writer);

        assertEquals("heading1,heading2\nsome text,\"more stuff\"\n", writer.toString());
    }

}