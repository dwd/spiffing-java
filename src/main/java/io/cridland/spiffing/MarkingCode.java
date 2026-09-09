package io.cridland.spiffing;

public enum MarkingCode {
    pageTop(1), pageBottom(2), documentEnd(4), noNameDisplay(8), noMarkingDisplay(16),
    documentStart(32), suppressClassName(64), replacePolicy(128);
    final int mask;

    MarkingCode(int mask) {
        this.mask = mask;
    }
}
