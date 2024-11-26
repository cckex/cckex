#include "ui/keytablewidget.h"

#include <QStringList>
#include <QTableWidget>
#include <QTableView>
#include <QHeaderView>

#include "ui/uihandler.h"
#include "common.h"

namespace Ui {

KeyTableWidget::KeyTableWidget(QWidget *parent) : QTableWidget(parent)
{
	QStringList tableHeaders = { "Type", "ID", "Key", "IV" };
	this->setColumnCount(tableHeaders.size());
	this->setHorizontalHeaderLabels(tableHeaders);
	this->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

	connect(UiHandler::getInstance(), &UiHandler::sig_resetKeyList, this, &KeyTableWidget::clearContents);

}

/*void KeyTableWidget::addNewEntry(cckex_key_entry_t &entry) {

	LOG_INFO << "addNewEntry: " << entry.type << std::endl;

	if (entry.type == cckex_key_type_t::INVALID) return;

	QString idStr = byteArrayToQString(entry.id);

	if (this->findItems(idStr, Qt::MatchExactly).size() != 0) return;

	int i = this->rowCount();

	this->insertRow(i);

	this->setItem(i, 0, new QTableWidgetItem(entry.type == cckex_key_type_t::MESSAGE_KEY ?
											"Message" : "Sealed Sender"));
	this->setItem(i, 1, new QTableWidgetItem(idStr));
	this->setItem(i, 2, new QTableWidgetItem(byteArrayToQString(entry.key)));
	this->setItem(i, 3, new QTableWidgetItem(entry.type == cckex_key_type_t::MESSAGE_KEY ? 
											byteArrayToQString(entry.iv) :
											""));
}*/

void KeyTableWidget::clearContents() {
	QTableWidget::clearContents();
	this->setRowCount(0);
}

KeyTableWidget::~KeyTableWidget() 
{

}

}	// namespace Ui
