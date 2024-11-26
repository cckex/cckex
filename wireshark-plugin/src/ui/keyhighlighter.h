
#pragma once

#include <QList>
#include <QObject>
#include <QTextDocument>
#include <QTextCharFormat>
#include <QRegularExpression>
#include <QSyntaxHighlighter>

namespace Ui {

class KeyHighlighter : QSyntaxHighlighter {

	Q_OBJECT

 public:

	explicit KeyHighlighter(QTextDocument *parent = nullptr);
	~KeyHighlighter();

 protected:

	void highlightBlock(const QString &text) override;

 private:

	typedef struct HighlightingRule {
		QRegularExpression pattern;
		QTextCharFormat format;
	} HighlightingRule_t;

	QList<HighlightingRule_t> _rules;

	QTextCharFormat _ssHeaderFormat;
	QTextCharFormat _msgHeaderFormat;
	QTextCharFormat _cckexEncKey;
	
};

}	// namespace Ui
