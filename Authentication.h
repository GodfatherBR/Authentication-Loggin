#pragma once
#include <vector>

namespace Users
{
	enum class LoginResult
	{
		Ok,
		FailedConnection,
		AccountLogged,
		ShortUserName,
		ShortPassword,
		WrongVersion,
		WrongPasswordOrUserName,
		ServerMaitenance,
		BlockedUser
	};


	struct SendLoginResult : PACKETCODE
	{
		LoginResult result;
	};

	struct UsersType
	{
		char UserName[32];
		INT64 HDSerial;
		INT64 ProcessadorCode;
		char Mac[30];
		int LevelMaster;
	};

	class Authentication
	{
		public:
			Authentication() = default;
			~Authentication() = default;
			static Authentication* GetInstance();
			void ReadGameMasterSQL();
			void ReadUsersBannedSQL();
			bool CheckUserBanned(LoginPacket* Login);
			bool CheckUserMaster(LoginPacket* Login = nullptr, rsPLAYINFO* player = nullptr);
			void InsertUserBanned(rsPLAYINFO* player) const;
			void LogAccountHandler(rsPLAYINFO* lpPlayInfo, LoginPacket* Login, SocketData* lpsmSock);
			void InsertAccountLogin(rsPLAYINFO* lpPlayInfo, LoginPacket* Login) const;
			LoginResult AuthenticateLogin(rsPLAYINFO* lpPlayInfo, LoginPacket* Login);
			std::vector<UsersType> getGameMaster() const;

	};
	static Authentication* GetAuthentication() { return Authentication::GetInstance(); };
}
