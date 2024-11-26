#include "ui/keyhighlighter.h"

namespace Ui {

KeyHighlighter::KeyHighlighter(QTextDocument *parent) : QSyntaxHighlighter(parent)
{

	// Create string formats for the specific cckex message headers. Then add the format together with the regular
	// expression (matching the message header) to the rules list.

	_msgHeaderFormat.setFontWeight(QFont::Bold);
	_msgHeaderFormat.setForeground(Qt::red);
	_rules.append({
		.pattern = QRegularExpression(QStringLiteral("ffff")),
		.format = _msgHeaderFormat
	});

	_ssHeaderFormat.setFontWeight(QFont::Bold);
	_ssHeaderFormat.setForeground(Qt::darkRed);
	_rules.append({
		.pattern = QRegularExpression(QStringLiteral("fffe")),
		.format = _ssHeaderFormat
	});

	_cckexEncKey.setFontWeight(QFont::Bold);
	_cckexEncKey.setForeground(Qt::blue);
	_rules.append({
		.pattern = QRegularExpression(QStringLiteral("cccc")),
		.format = _ssHeaderFormat
	});
}

void KeyHighlighter::highlightBlock(const QString &text)
{

	// First iterate over all highlight rules. In the loop match the regex of the current rule with the text.
	// Iterate over all matches and set the format of the matched text to the format of the current rule.

	for(const HighlightingRule_t &rule : std::as_const(_rules)) {
		QRegularExpressionMatchIterator iter = rule.pattern.globalMatch(text);
		while(iter.hasNext()) {
			QRegularExpressionMatch match = iter.next();
			setFormat(match.capturedStart(), match.capturedLength(), rule.format);
		}
	}

}

KeyHighlighter::~KeyHighlighter()
{

}

}	// namespace Ui
