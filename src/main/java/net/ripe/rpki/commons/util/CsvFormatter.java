package net.ripe.rpki.commons.util;

import org.apache.commons.lang3.Validate;

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

    private List<CsvColumn> columns = new ArrayList<>();

    private final Map<CsvColumn, List<String>> rowValues = new HashMap<>();

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
        rowValues.put(column, new ArrayList<>());
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
        out.write(headerLine + "\n");
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
        out.write(rowOutput + "\n");
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


    static class CsvColumn {
        private final String heading;
        private final boolean quoteValues;

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
