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

import org.apache.commons.lang.Validate;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CsvFormatter {

    private static final char QUOTE_CHAR = '"';

    private static final String SEPARATOR = ",";

    private List<CsvColumn> columns = new ArrayList<CsvColumn>();

    private Map<CsvColumn, List<String>> rowValues = new HashMap<CsvColumn, List<String>>();

    private int rows = 0;

    private final String separator;

    public CsvFormatter() {
        this(SEPARATOR);
    }

    public CsvFormatter(String separator) {
        this.separator = separator;
    }

    public CsvFormatter addColumn(String heading) {
        addColumn(heading, false);
        return this;
    }

    public CsvFormatter addQuotedColumn(String heading) {
        addColumn(heading, true);
        return this;
    }

    private void addColumn(String heading, boolean quoteValues) {
        CsvColumn column = new CsvColumn(heading, quoteValues);
        columns.add(column);
        rowValues.put(column, new ArrayList<String>());
    }

    // Setters for testing
    void setColumnList(List<CsvColumn> columns) {
        this.columns = columns;
    }


    public CsvFormatter addLine(String... values) {
        Validate.isTrue(columns.size() == values.length);
        int columnIndex = 0;

        for (String value : values) {
            if (value == null) {
                value = "";
            }

            CsvColumn column = columns.get(columnIndex);

            if (!column.hasQuoteValues()) {
                Validate.isTrue(!value.contains(separator));
            }

            rowValues.get(column).add(value);
            columnIndex++;
        }
        rows++;

        return this;
    }


    public void print(File outputFile) throws IOException {
        FileWriter fileWriter = new FileWriter(outputFile);
        print(fileWriter, true);
        fileWriter.close();
    }

    public void printWithoutHeaders(Writer out) throws IOException {
        print(out, false);
    }

    public void printWithHeaders(Writer out) throws IOException {
        print(out, true);
    }

    private void print(Writer out, boolean printHeaders) throws IOException {
        if (printHeaders) {
            printHeaders(out);
        }

        for (int i = 0; i < rows; i++) {
            printRow(out, i);
        }
    }

    private void printHeaders(Writer out) throws IOException {
        StringBuilder headerLine = new StringBuilder();

        int columnNumber = 1;
        int numberOfColmns = columns.size();
        for (CsvColumn col : columns) {
            headerLine.append(col.getHeading());
            if (columnNumber < numberOfColmns) {
                headerLine.append(separator);
            }
            columnNumber++;
        }
        out.write(headerLine.toString() + "\n");
    }

    private void printRow(Writer out, int i) throws IOException {
        StringBuilder rowOutput = new StringBuilder();

        int columnNumber = 1;
        int numberOfColumns = columns.size();

        for (CsvColumn col : columns) {
            printValue(i, rowOutput, col);
            if (columnNumber < numberOfColumns) {
                rowOutput.append(separator);
            }
            columnNumber++;
        }
        out.write(rowOutput.toString() + "\n");
    }

    private void printValue(int i, StringBuilder rowOutput, CsvColumn col) {
        if (col.hasQuoteValues()) {
            rowOutput.append(QUOTE_CHAR);
        }

        rowOutput.append(rowValues.get(col).get(i));

        if (col.hasQuoteValues()) {
            rowOutput.append(QUOTE_CHAR);
        }
    }


    class CsvColumn {
        private String heading;
        private boolean quoteValues;

        public CsvColumn(String heading, boolean quoteValues) {
            this.heading = heading;
            this.quoteValues = quoteValues;
        }

        public String getHeading() {
            return heading;
        }

        public boolean hasQuoteValues() {
            return quoteValues;
        }
    }
}
