#include "ui/keysfiletab.h"

#include <QLabel>
#include <QVBoxLayout>

#include "message_dissection/signalmessagecrypto.h"
#include "ui/uihandler.h"
#include "common.h"

namespace Ui {

KeysFileTab::KeysFileTab(QWidget *parent) : QWidget(parent) 
{
	QCheckBox *enableKeyFileCheckBox = new QCheckBox("Enable Key File", this);
	enableKeyFileCheckBox->setCheckState(Qt::CheckState::Unchecked);
	enableKeyFileCheckBox->setToolTip(tr("Warning: Changing this will reset the raw CC data and key list and will trigger a reload."));

	connect(enableKeyFileCheckBox, &QCheckBox::toggled,
		this, &KeysFileTab::_slot_keyFileEnableCheckboxChanged);

	QLabel *keyEntryTableLabel = new QLabel(tr("Loaded Keys:"), this);
	_keyEntryTable = new KeyTableWidget(this);

	LOG_INFO << "connect addNewfileKeyEntry to addNewEntry" << std::endl;

//	connect(UiHandler::getInstance(), &UiHandler::sig_newFileKeyEntryAdded,
//			_keyEntryTable			, &KeyTableWidget::addNewEntry);

	QVBoxLayout *layout = new QVBoxLayout(this);
	layout->addWidget(enableKeyFileCheckBox);
	layout->addWidget(keyEntryTableLabel);
	layout->addWidget(_keyEntryTable);
	layout->addStretch(1);

	this->setLayout(layout);
}

void KeysFileTab::_slot_keyFileEnableCheckboxChanged(bool checked)
{
	if(!checked) {
		disable_key_file();
	} else {
		enable_key_file();
	}
}

KeysFileTab::~KeysFileTab()
{

}

}	// namespace Ui
