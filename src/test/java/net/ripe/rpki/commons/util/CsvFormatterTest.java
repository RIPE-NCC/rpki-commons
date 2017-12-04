/**
 * The BSD License
 *
 * Copyright (c) 2010-2018 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.commons.util;

/**
 * @author thies (thies@te-con.nl)
 *         Date: 1/26/11 11:53 AM
 */

import net.ripe.rpki.commons.util.CsvFormatter.CsvColumn;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

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
        Assert.assertEquals(1, columns.size());
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
    public void shouldRejectLinesWhenSeparatorIsUsedInUnquotedField() {
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

        Assert.assertEquals("some text,\"more stuff\"\n", writer.toString());
    }


    @Test
    public void shouldChangeSeparator() throws IOException {
        subject = new CsvFormatter(";");
        subject.addColumn("heading1");
        subject.addColumn("heading2");

        String val1 = "text";
        String val2 = "stuff";
        subject.addLine(val1, val2);

        StringWriter writer = new StringWriter();
        subject.printWithoutHeaders(writer);

        Assert.assertEquals("text;stuff\n", writer.toString());
    }

    @Test
    public void shouldUseEmptyStringForNullValues() throws IOException {
        subject.addColumn("heading1");
        subject.addColumn("heading2");

        String val1 = null;
        subject.addLine(val1, val1);

        StringWriter writer = new StringWriter();
        subject.printWithoutHeaders(writer);

        Assert.assertEquals(",\n", writer.toString());
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

        Assert.assertEquals("heading1,heading2\nsome text,\"more stuff\"\n", writer.toString());
    }

}