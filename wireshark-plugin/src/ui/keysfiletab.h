
#pragma once

#include <QObject>
#include <QWidget>
#include <QCheckBox>

#include "message_dissection/keylist.h"
#include "ui/keytablewidget.h"

namespace Ui {

class KeysFileTab : public QWidget {

	Q_OBJECT

 public:

	explicit KeysFileTab(QWidget *parent = nullptr);
	~KeysFileTab();

 protected slots:

	void _slot_keyFileEnableCheckboxChanged(bool state);

 private:

	KeyTableWidget *_keyEntryTable;

};

}	// namespace Ui
