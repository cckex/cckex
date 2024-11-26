#include "ui/cctab.h"

#include <QLabel>
#include <QVBoxLayout>
#include <QTableWidgetItem>
#include <QStringList>

#include "ui/keyhighlighter.h"
#include "ui/uihandler.h"
#include "common.h"

namespace Ui {

CCTab::CCTab(QWidget *parent) : QWidget(parent)
{
	QLabel *rawChannelDataLabel = new QLabel(tr("Raw Covert Channel Data:"), this);
	_rawChannelDataTextEdit = new QTextEdit(this);
	connect(UiHandler::getInstance(), &UiHandler::sig_reset,
		 _rawChannelDataTextEdit, &QTextEdit::clear);

	KeyHighlighter *highlighter = new KeyHighlighter(_rawChannelDataTextEdit->document());
	(void) highlighter;

	QLabel *keyEntryTableLabel = new QLabel(tr("Retrieved Keys"), this);
	_keyEntryTable = new KeyTableWidget(this);

	QVBoxLayout *layout = new QVBoxLayout(this);
	layout->addWidget(rawChannelDataLabel);
	layout->addWidget(_rawChannelDataTextEdit);
	layout->addSpacing(10);
	layout->addWidget(keyEntryTableLabel);
	layout->addWidget(_keyEntryTable);
	layout->addStretch(1);
	
	this->setLayout(layout);
}

/*void CCTab::addNewKeyEntry(cckex_key_entry_t &entry) 
{
	LOG_INFO << "adding new key" << std::endl;
	_keyEntryTable->addNewEntry(entry);
}*/

void CCTab::addRawData(QString data)
{
	_rawChannelDataTextEdit->clear();
	_rawChannelDataTextEdit->append(data);
}

CCTab::~CCTab()
{

}

}	// namespace Ui
