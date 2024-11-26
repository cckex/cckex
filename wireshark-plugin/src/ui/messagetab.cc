#include "ui/messagetab.h"

#include <QLabel>
#include <QStringList>
#include <QVBoxLayout>
#include <QTableWidgetItem>
#include <QHeaderView>

#include "ui/uihandler.h"

namespace Ui {

MessageTab::MessageTab(QWidget *parent) : QWidget(parent)
{
	QStringList tableHeaders = { "Pkg_Num", "Type", "Content" };

	QLabel *messageTableLabel = new QLabel(tr("Decrypted Messages:"), this);
	_messageTable = new QTableWidget();
	_messageTable->setColumnCount(tableHeaders.size());
	_messageTable->setHorizontalHeaderLabels(tableHeaders);
	_messageTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

	connect(UiHandler::getInstance(), &UiHandler::sig_messageAdded,
		this, &MessageTab::slot_addMessage);

	QVBoxLayout *layout = new QVBoxLayout();
	layout->addWidget(messageTableLabel);
	layout->addWidget(_messageTable);

	this->setLayout(layout);
}

void MessageTab::slot_addMessage(int num, int type, QString text) 
{
	LOG_INFO << "num=" << num << " type=" << type << " text=" << text.toStdString() << std::endl;

	QString numStr = QString::number(num);

	if(_messageTable->findItems(numStr, Qt::MatchExactly ).size() != 0) return;

	int i = _messageTable->rowCount();

	_messageTable->insertRow(i);
	
	_messageTable->setItem(i, 0, new QTableWidgetItem(numStr));

	if (type == 0x32) {
		_messageTable->setItem(i, 1, new QTableWidgetItem("Typing"));
		_messageTable->setItem(i, 2, new QTableWidgetItem("-"));
	} else if (type == 0x0a) {
		_messageTable->setItem(i, 1, new QTableWidgetItem("Text"));
		_messageTable->setItem(i, 2, new QTableWidgetItem(text));
	} else {
		_messageTable->setItem(i, 1, new QTableWidgetItem("Unknown"));
		_messageTable->setItem(i, 2, new QTableWidgetItem("-"));
	}

}

MessageTab::~MessageTab()
{

}

}	// namespace Ui
