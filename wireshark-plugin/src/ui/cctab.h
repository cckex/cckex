
#pragma once

#include <QObject>
#include <QWidget>
#include <QTextEdit>

#include "message_dissection/keylist.h"
#include "extraction/keytypes/signal_common.h"
#include "ui/keytablewidget.h"

namespace Ui {

class CCTab : public QWidget {
	Q_OBJECT

 public:

	explicit CCTab(QWidget *parent = nullptr);
	~CCTab();

public slots:

	void addRawData(QString data);
//	void addNewKeyEntry(cckex_key_entry_t &entry);

private:

	QTextEdit *_rawChannelDataTextEdit;
	KeyTableWidget *_keyEntryTable;

};

}	// namespace Ui
