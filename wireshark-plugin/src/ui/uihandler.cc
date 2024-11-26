#include "ui/uihandler.h"

#include <QApplication>

#include <epan/plugin_if.h>

#include "message_dissection/signalmessagecrypto.h"
#include "ui/mainpluginui.h"
#include "common.h"

namespace Ui {

QMutex *UiHandler::singletonMutex = new QMutex();

UiHandler::UiHandler()
{
	connect(this, &UiHandler::sig_reset, this, &UiHandler::sig_resetKeyList);
	connect(this, &UiHandler::sig_reset, this, &UiHandler::sig_resetRawData);
	connect(this, &UiHandler::sig_resetKeyList, this, &UiHandler::slot_resetKeyList);
	connect(this, &UiHandler::sig_resetRawData, this, &UiHandler::slot_resetCCData);
}

UiHandler *UiHandler::getInstance()
{
	static UiHandler *uiHandler = nullptr;

	QMutexLocker locker(singletonMutex);

	if(uiHandler == nullptr) {
		uiHandler = new UiHandler();
	}

	return uiHandler;
}

void UiHandler::runMainDialog()
{
	MainPluginUi *mainui = new MainPluginUi();

	bool hasGui = (qobject_cast<QApplication*>(QCoreApplication::instance()) != nullptr);

	if(hasGui) {

		mainui->show();

	} else {

		// Boilerplate for running the correct app context
		int argc = 1;
		char *argv = (char*)"cckexplugin";

		QApplication app(argc, &argv);

		mainui->show();

		app.exec();
	}

	// reset and load key data
	reset_keys();
	load_keys_from_file(config_get_signal_key_file());
	check_for_new_keys();
}

void UiHandler::doReset()
{
	emit sig_reset();
}

void UiHandler::doResetKeyList()
{
	emit sig_resetKeyList();
}

/*void UiHandler::addNewCChannelKeyEntry(cckex_key_entry_t &entry)
{
	emit sig_newCChannelKeyEntryAdded(entry);
}

void UiHandler::addNewSignalKeyEntry(cckex_key_entry_t &entry)
{
	emit sig_newSignalKeyEntryAdded(entry);
}*/

void UiHandler::addRawCCData(UiCCType type, std::vector<uint8_t> byteVec)
{
	QByteArray array(reinterpret_cast<const char*>(byteVec.data()), byteVec.size());

	QString stringData(array.toHex());

	if(type == UiCCType::CLASSIC) {
		emit sig_addRawClassicCCData(stringData);
	} else {
		emit sig_addRawSignalCCData(stringData);
	}
}

void UiHandler::addMessage(int num, int type, QString text)
{
	LOG_INFO << "num=" << num << " type=" << type << " text=" << text.toStdString() << std::endl;

	emit sig_messageAdded(num, type, text);
}

/*void UiHandler::addNewFileKeyEntry(cckex_key_entry_t &entry)
{
	LOG_INFO << "emit newFileKeyEntryAdded" << std::endl;

	emit sig_newFileKeyEntryAdded(entry);
}*/

void UiHandler::slot_resetKeyList()
{
	reset_keys();	
}

void UiHandler::slot_resetCCData()
{
	reset_ccdata();
}

}	// namespace Ui

extern "C" {

	static void _cckex_menu_cb(ext_menubar_gui_type gui_type, gpointer gui_data, gpointer user_data _U_) {
		(void) gui_type;
		(void) gui_data;

		CLOG_INFO("starting cckex gui");

		Ui::UiHandler::getInstance()->runMainDialog();
	}

}

CCKEX_API void setup_cckex_wireshark_toolbar(int proto_cckex)
{
	ext_menu_t *menu = ext_menubar_register_menu(proto_cckex, "CCKex", TRUE);
	ext_menubar_set_parentmenu(menu, "Tools");

	ext_menubar_add_entry(menu, "GUI", "GUI for the CCKex Wireshark Plugin", _cckex_menu_cb, NULL);
}

CCKEX_API void reset_cckex_wireshark_ui(void)
{
	Ui::UiHandler::getInstance()->doReset();
}

CCKEX_API void uihandler_add_message(int num, int type, const char *text)
{
	Ui::UiHandler::getInstance()->addMessage(num, type, text);
}
