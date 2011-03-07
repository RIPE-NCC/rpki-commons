package net.ripe.certification.csv;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.Validate;

public class CsvFormatter {

    private static final char QUOTE_CHAR = '"';

    private static final String SEPERATOR = ",";

    private List<CsvColumn> columns = new ArrayList<CsvColumn>();

    private Map<CsvColumn, List<String>> rowValues = new HashMap<CsvColumn, List<String>>();

    private int rows = 0;


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
                Validate.isTrue(!value.contains(SEPERATOR));
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
                headerLine.append(SEPERATOR);
            }
            columnNumber++;
        }
        out.write(headerLine.toString() + "\n");
    }

    private void printRow(Writer out, int i) throws IOException {
        StringBuilder rowOutput = new StringBuilder();

        int columnNumber = 1;
        int numberOfColmns = columns.size();

        for (CsvColumn col : columns) {
            printValue(i, rowOutput, col);
            if (columnNumber < numberOfColmns) {
                rowOutput.append(SEPERATOR);
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
