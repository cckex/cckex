
#pragma once

#include <QObject>
#include <QWidget>
#include <QTableWidget>

#include "message_dissection/keylist.h"

namespace Ui {

class KeyTableWidget : public QTableWidget {
	
	Q_OBJECT

 public:
	
	explicit KeyTableWidget(QWidget *parent = nullptr);
	~KeyTableWidget();

 public slots:

//	void addNewEntry(cckex_key_entry_t &entry);

	void clearContents();
};

}	// namespace Ui
