
#pragma once

#include "common.h"

#ifdef __cplusplus

#include "message_dissection/keylist.h"

#include <QObject>
#include <QMutex>

namespace Ui {

enum UiCCType {
	CLASSIC = 0,
	TLS = 1,
	SIGNAL = 2
};

class UiHandler : public QObject {

	Q_OBJECT

 public:

	static UiHandler *getInstance();

	void runMainDialog();

	void doReset();
	void doResetKeyList();

/*	void addNewCChannelKeyEntry(cckex_key_entry_t &entry);
	void addNewSignalKeyEntry(cckex_key_entry_t &entry);
	void addNewFileKeyEntry(cckex_key_entry_t &entry);*/

	void addRawCCData(UiCCType type, std::vector<uint8_t> byteVec); 

	void addMessage(int num, int type, QString text);

 signals:

	void sig_reset();
	void sig_resetKeyList();
	void sig_resetRawData();

	/*void sig_newCChannelKeyEntryAdded(cckex_key_entry_t &entry);
	void sig_newSignalKeyEntryAdded(cckex_key_entry_t &entry);
	void sig_newFileKeyEntryAdded(cckex_key_entry_t &entry);*/

	void sig_addRawClassicCCData(QString data);
	void sig_addRawSignalCCData(QString data);

	void sig_messageAdded(int num, int type, QString text);

protected slots:

	void slot_resetKeyList();
	void slot_resetCCData();

 private:

	// nothing to do in constructor for now
	UiHandler();

	// dont allow copy or assigment of singleton
	/*UiHandler(UiHandler const&)				= delete;
	UiHandler(UiHandler &&)					= delete;
	UiHandler& operator=(UiHandler const&)	= delete;
	UiHandler& operator=(UiHandler &&)		= delete;*/

	static QMutex *singletonMutex;

};

}	// namespace Ui

#endif

CCKEX_API void setup_cckex_wireshark_toolbar(int proto_cckex);
CCKEX_API void reset_cckex_wireshark_ui(void);

CCKEX_API void uihandler_add_message(int num, int type, const char *text);
