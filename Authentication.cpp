#include "Pch.h"
#include "Authentication.h"
#include "Modules/Database/SQLConnection.h"
#include "Modules/ServerConfiguration/ServerConfig/ServerConfig.h"
#include "CharacterGame/record.h"
#include "SrcServer/onserver.h"

namespace Users
{
	std::vector<UsersType>UsersBanned;
	std::vector<UsersType>GameMaster;

	Authentication* Authentication::GetInstance()
	{
		static Authentication Instance;
		return &Instance;
	}

	void Authentication::ReadGameMasterSQL()
	{
		GameMaster.clear();
		if (auto db = GetSubsystem<SQLConnection>().GetConnection(DATABASEID_UserDB); db && db->Open())
		{           
			if (db->Prepare("SELECT UserName,HDSerial,ProcessadorCode,Mac,LevelMaster FROM UsersMaster"))
			{
				db->Execute(FALSE);
				while (db->NextRow())
				{
					UsersType UsersGM{};
					db->GetData(1, PARAMTYPE_String, UsersGM.UserName, sizeof(UsersGM.UserName));
					db->GetData(2, PARAMTYPE_Int64, &UsersGM.HDSerial);
					db->GetData(3, PARAMTYPE_Int64, &UsersGM.ProcessadorCode);
					db->GetData(4, PARAMTYPE_String, UsersGM.Mac, sizeof(UsersGM.Mac));
					db->GetData(5, PARAMTYPE_Integer, &UsersGM.LevelMaster);

					GameMaster.push_back(UsersGM);
				}
			}
			db->Close();
		}
	}

	void Authentication::ReadUsersBannedSQL()
	{
		UsersBanned.clear();
		if (auto db = GetSubsystem<SQLConnection>().GetConnection(DATABASEID_UserDB);db && db->Open())
		{           
			if (db->Prepare("SELECT HDSerial,ProcessadorCode,Mac FROM UsersBanned"))
			{             
				db->Execute(FALSE);
				while (db->NextRow())
				{
					UsersType UsersB{};
					db->GetData(1, PARAMTYPE_Int64, &UsersB.HDSerial);
					db->GetData(1, PARAMTYPE_Int64, &UsersB.ProcessadorCode);
					db->GetData(1, PARAMTYPE_String, UsersB.Mac,sizeof(UsersB.Mac));

					UsersBanned.push_back(UsersB);
				}
			}
			db->Close();
		}
	}    

	bool Authentication::CheckUserBanned(LoginPacket* Login)
	{
		bool result = false;
		for (auto& Banned : UsersBanned)
		{
			if ((_strcmpi(Banned.UserName, Login->account) == 0) || (Banned.HDSerial == Login->Serial) ||
			(Banned.ProcessadorCode == Login->processorCode) || _strcmpi(Banned.Mac, Login->mac) == 0)
				result = true;
		}
		return result;
	}

	bool Authentication::CheckUserMaster(LoginPacket* Login, rsPLAYINFO* player)
	{
		bool result = false;
		for (auto& Master : GameMaster)
		{
			if (Login)
			{
				if ((_strcmpi(Master.UserName, Login->account) == 0) || ((Master.HDSerial == Login->Serial) &&
					(Master.ProcessadorCode == Login->processorCode) && _strcmpi(Master.Mac, Login->mac) == 0))
					result = true;				   
			}
			if (player)
			{
				if ((_strcmpi(Master.UserName, player->szID) == 0) || ((Master.HDSerial == player->HDSerial) &&
					(Master.ProcessadorCode == player->ProcessorCode) && _strcmpi(Master.Mac, player->MacAdress) == 0))
				{
					result = true;
					player->AdminMode = Master.LevelMaster;
				}
			}
		}
		return result;
	}

	void Authentication::InsertUserBanned(rsPLAYINFO* player) const
	{
		
		if (auto db = GetSubsystem<SQLConnection>().GetConnection(DATABASEID_UserDB); db && db->Open())
		{                               
			if (db->Prepare("INSERT INTO UsersBanned VALUES (?,?,?,?,GETDATE())"))
			{
				UsersType UsersB{};
				strcpy_s(UsersB.UserName, player->szID);
				UsersB.HDSerial = player->HDSerial;
				UsersB.ProcessadorCode = player->ProcessorCode;
				strcpy_s(UsersB.Mac, player->MacAdress);

				db->BindInputParameter(UsersB.UserName, 1, PARAMTYPE_String);
				db->BindInputParameter(&UsersB.HDSerial, 2, PARAMTYPE_Int64);
				db->BindInputParameter(&UsersB.ProcessadorCode, 3, PARAMTYPE_Int64);
				db->BindInputParameter(UsersB.Mac, 4, PARAMTYPE_String);
				db->Execute();

				UsersBanned.push_back(UsersB);				
			}
			db->Close();
		}
	}

	void Authentication::InsertAccountLogin(rsPLAYINFO* lpPlayInfo, LoginPacket* Login) const
	{
		
		INT64 SerialTemp = Login->Serial;
		INT64 ProcessadorTemp = Login->processorCode;
		char ip[30] = { 0 };
		strcpy_s(ip, sizeof(ip), lpPlayInfo->lpsmSock->GetIPAddress());

		if (auto db = GetSubsystem<SQLConnection>().GetConnection(DATABASEID_LogDB); db && db->Open())
		{
			if (db->Prepare("INSERT INTO AccountLogin VALUES (?,?,?,?,?,?,?,GETDATE())"))
			{
				db->BindInputParameter(Login->account, 1, PARAMTYPE_String);
				db->BindInputParameter(Login->password, 2, PARAMTYPE_String);
				db->BindInputParameter(ip, 3, PARAMTYPE_String);
				db->BindInputParameter(Login->mac, 4, PARAMTYPE_String);
				db->BindInputParameter(&SerialTemp, 5, PARAMTYPE_Int64);
				db->BindInputParameter(&ProcessadorTemp, 6, PARAMTYPE_Int64);
				db->BindInputParameter(&Login->pcName, 7, PARAMTYPE_String);
				db->Execute();
			}
			db->Close();
		}		
	}

	LoginResult Authentication::AuthenticateLogin(rsPLAYINFO* lpPlayInfo, LoginPacket* Login)
	{
		LoginResult result = LoginResult::FailedConnection;

		char _Password[32] = { 0 };   
		bool AccountLogged = false;

		for (int cnt = 0; cnt < CONNECTMAX; cnt++)
		{
			if (rsPlayInfo[cnt].lpsmSock && rsPlayInfo[cnt].szID[0])
			{
				if (_strcmpi(Login->account, rsPlayInfo[cnt].szID) == 0)
				{                           
					if (rsPlayInfo[cnt].dwObjectSerial)
					{
						AccountLogged = true;
						break;
					}
				}
			}
		}

		if (!AccountLogged)
		{
			if (auto db = GetSubsystem<SQLConnection>().GetConnection(DATABASEID_UserDB); db && db->Open())
			{
				if (db->Prepare("SELECT Password FROM Users WHERE AccountID =?"))
				{
					db->BindInputParameter(Login->account, 1, PARAMTYPE_String);

					if (db->Execute())
					{
						db->GetData(1, PARAMTYPE_String, _Password, sizeof(_Password));

						if (std::strcmp(_Password, Login->password) == 0)
						{
							result = LoginResult::Ok;
							rsRECORD_DBASE* lpRecordBase = nullptr;

							try
							{
								lpRecordBase = new rsRECORD_DBASE;
								lpPlayInfo->CharLevelMax =	lpRecordBase->SendUserDataToClient(Login->account, lpPlayInfo->lpsmSock, 0);
								delete lpRecordBase;
							}
							catch (...)
							{
								lpRecordBase = nullptr;
							}

							extern int rsSendServerList(SocketData * lpsmSock, int ClanTicket);
							extern int rsLoadCastleInfo();
							rsSendServerList(lpPlayInfo->lpsmSock, 0);

							extern int	LoginServer;
							LoginServer = TRUE;

							if (!rsBlessCastle.CastleMode) rsLoadCastleInfo();
						}
						else
						{
							result = LoginResult::WrongPasswordOrUserName;
						}
					}
					else
					{
						result = LoginResult::WrongPasswordOrUserName;
					}

				}
				db->Close();
			}
		}
		else
			result = LoginResult::AccountLogged;

		return result;
	}

	std::vector<UsersType> Authentication::getGameMaster() const
	{
		return GameMaster;
	}

	void Authentication::LogAccountHandler(rsPLAYINFO* lpPlayInfo, LoginPacket* Login, SocketData* lpsmSock)
	{
		LoginResult resultLogin = LoginResult::FailedConnection;
		bool GameMasterMode = false;

		strcpy_s(lpPlayInfo->szID, Login->account);
		lpPlayInfo->dwCode_ID = GetSpeedSum(lpPlayInfo->szID);
		lpPlayInfo->Client_Version = Login->ClientVersion;
		strcpy_s(lpPlayInfo->MacAdress, Login->mac);
		lpPlayInfo->HDSerial = Login->Serial;
		lpPlayInfo->ProcessorCode = Login->processorCode;


		if (Login->PacketPass != 0xAE)        
			resultLogin = LoginResult::FailedConnection;
		else
			lpPlayInfo->bAuthorized = true;

		InsertAccountLogin(lpPlayInfo, Login);

		if (configuration.bMaintenanceMode)
		{
			resultLogin = LoginResult::ServerMaitenance;
			GameMasterMode = CheckUserMaster(Login);

		}
		if (GameMasterMode || resultLogin != LoginResult::ServerMaitenance)
		{
			if (GameMasterMode || !CheckUserBanned(Login))
			{
				resultLogin = AuthenticateLogin(lpPlayInfo, Login);
			}
			else
			{
				resultLogin = LoginResult::BlockedUser;
			}
		}

		if (resultLogin != LoginResult::Ok)
		{
			SendLoginResult SendFailedResult;
			SendFailedResult.iHeader = PacketCode::FAILCONNECT;
			SendFailedResult.iLength = sizeof(SendLoginResult);
			SendFailedResult.result = resultLogin;
			lpsmSock->LegacySend((char*)&SendFailedResult, SendFailedResult.iLength, TRUE);
		}
	}
}