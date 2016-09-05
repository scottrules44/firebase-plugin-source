--[[ database premissons
{
  "rules": {
    ".read": "auth != null",
    ".write": "auth != null",
  }
}
]]--
local m = {}
--if (system.getInfo( "environment" ) == "simulator") then
	print( "This is a beta, which only works in simulator, please get the full plugin when it becomes available" )
	local json = require( "json" )
	m.myUrl = ""
	local authUrl = "https://accounts.google.com/o/oauth2/auth"
	local tokenAuth="https://accounts.google.com/o/oauth2/token"
	local fileName = "firebase.json"
	local myAccessToken
	m.myKey = ""
	m.databaseSecret = ""
	--firebase variable 
	m.get = "GET"
	m.put = "PUT"
	m.post = "POST"
	m.delete = "DELETE" 
	m.patch = "PATCH" 
	m.isLoginedIn = false
	m.haveRefreshToken = false
	m.myCode = nil

	local myInfo = {}

	function string:split( inSplitPattern, outResults )
	 
	   if not outResults then
	      outResults = {}
	   end
	   local theStart = 1
	   local theSplitStart, theSplitEnd = string.find( self, inSplitPattern, theStart )
	   while theSplitStart do
	      table.insert( outResults, string.sub( self, theStart, theSplitStart-1 ) )
	      theStart = theSplitEnd + 1
	      theSplitStart, theSplitEnd = string.find( self, inSplitPattern, theStart )
	   end
	   table.insert( outResults, string.sub( self, theStart ) )
	   return outResults
	end

	local function doesFileExist( fname, path )

	    local results = false

	    -- Path for the file
	    local filePath = system.pathForFile( fname, path )

	    if ( filePath ) then
	        local file, errorString = io.open( filePath, "r" )

	        if not file then
	            -- Error occurred; output the cause
	        else
	            results = true
	            -- Close the file handle
	            file:close()
	        end
	    end

	    return results
	end

	local hex_to_char = function(x)
	  return string.char(tonumber(x, 16))
	end

	local function decodeURI(s)
	  return s:gsub("%%(%x%x)", hex_to_char)
	end
	function string.urlEncode( str )
	   if ( str ) then
	      str = string.gsub( str, "\n", "\r\n" )
	      str = string.gsub( str, "([^%w ])",
	         function (c) return string.format( "%%%02X", string.byte(c) ) end )
	      str = string.gsub( str, " ", "+" )
	   end
	   return str
	end
	local function urlencode(str)
	  if (str) then
	    str = string.gsub (str, "\n", "\r\n")
	    str = string.gsub (str, "([^%w ])",
	        function (c) return string.format ("%%%02X", string.byte(c)) end)
	    str = string.gsub (str, " ", "+")
	  end
	  return str    
	end
	local firebaseScope = "https://www.googleapis.com/auth/plus.login"
	local function refreshToken(  )
	    local file = io.open(system.pathForFile(fileName, system.DocumentsDirectory), "r")
	    -- First, check if it's a saved refresh token, so we can authenticate user automatically
	    if file then
	        --print("OAuth2.connect: Requesting Token using refreshToken")
	        local account = json.decode(file:read( "*a" ))
	        if (account and account["refreshToken"]) then
	            return true
	        else
	            return false
	        end
	    end
	end
	local function saveRefreshToken( token, localId )
		local file = io.open(system.pathForFile(fileName, system.DocumentsDirectory), "w")
	    if file then
	        file:write( json.encode({refreshToken = token, localId= localId}) )
	        io.close( file )
	    end
	end
	m.haveRefreshToken = refreshToken()
	function m.quickLogin( lis )
		if (m.haveRefreshToken == true) then
			local file = io.open(system.pathForFile(fileName, system.DocumentsDirectory), "r")
			local account = json.decode(file:read( "*a" ))
			local refreshToken = account["refreshToken"]
			network.request( "https://securetoken.googleapis.com/v1/token?grant_type=refresh_token&refresh_token="..refreshToken.."&key="..urlencode(m.myKey), "POST", function ( e )
				if (e.status == 200) then
					local tempTable2 =json.decode(e.response)
					saveRefreshToken( tempTable2.refresh_token, tempTable2.user_id )
					myInfo = tempTable2
					m.isLoginedIn = true
					lis({error = nil, isError = false, response = "logined"})
				else
					lis({error = "request failed", isError = true, response = nil})
				end
			end )
		else
			lis({error = "please do a full login", isError = true, response = nil})
		end
	end
	function m.login( email, password, lis, haveVerf )
		local setVerf = false
		if (haveVerf ~= nil and haveVerf == true) then
			setVerf = true
		end
		local headers = {}
		local body = {}
		body.email = email
		body.password = password
		body.returnSecureToken = true
		headers["Content-Type"] = "application/json"
		network.request( "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key="..urlencode(m.myKey), "POST", function (e)
			if (e.status == 200) then
				local tempTable2
				local tempTable3 =json.decode(e.response)
				network.request( "https://securetoken.googleapis.com/v1/token?grant_type=refresh_token&refresh_token="..tempTable3.refreshToken.."&key="..urlencode(m.myKey), "POST", function ( ev )
					if (ev.status == 200) then
						if (setVerf== true) then
							network.request( "https://www.googleapis.com/identitytoolkit/v3/relyingparty/getAccountInfo?key="..urlencode(m.myKey), "POST", function ( event )
								if (event.status == 200 and event.response) then
									local tempTable4 = json.decode( event.response )
									if (tempTable4 and tempTable4.users and tempTable4.users[1] and tempTable4.users[1].emailVerified and tempTable4.users[1].emailVerified == true) then
										tempTable2 =json.decode(ev.response)
										saveRefreshToken( tempTable2.refresh_token, tempTable2.user_id )
										myInfo = tempTable2
										lis({error = nil, isError = false, response = "logined"})
										m.isLoginedIn = true
										myInfo = tempTable2
									else
										lis({error = "email not verified", isError = true, response = nil})
									end
								else
									lis({error = "request failed: "..event.response, isError = true, response = nil})
								end
							end, {headers = headers, body= json.encode({idToken= tempTable3.idToken})} )
						else
							tempTable2 =json.decode(ev.response)
							saveRefreshToken( tempTable2.refresh_token, tempTable2.user_id )
							myInfo = tempTable2
							lis({error = nil, isError = false, response = "logined"})
							m.isLoginedIn = true
							myInfo = tempTable2
						end
					else
						lis({error = "request failed: "..ev.response, isError = true, response = nil})
					end
				end )
			else
				lis({error = "request failed: "..e.response, isError = true, response = nil})
			end
		end, {headers = headers, body= json.encode(body)} )
	end
	function m.loginWithSocial( access_token, providerId, requestUri,lis )
		local setVerf = false
		if (haveVerf ~= nil and haveVerf == true) then
			setVerf = true
		end
		local headers = {}
		headers["Content-Type"] = "application/json"
		local body = {}
		body.postBody = "access_token="..access_token.."&providerId="..providerId
		body.requestUri=""
		body.returnSecureToken = true
		network.request( "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyAssertion?key="..urlencode(m.myKey), "POST", function (e)
			if (e.status == 200) then
				local tempTable2
				local tempTable3 =json.decode(e.response)
				network.request( "https://securetoken.googleapis.com/v1/token?grant_type=refresh_token&refresh_token="..tempTable3.refreshToken.."&key="..urlencode(m.myKey), "POST", function ( ev )
					if (ev.status == 200) then
						network.request( "https://www.googleapis.com/identitytoolkit/v3/relyingparty/getAccountInfo?key="..urlencode(m.myKey), "POST", function ( event )
							if (event.status == 200 and event.response) then
								local tempTable4 = json.decode( event.response )
								tempTable2 =json.decode(ev.response)
								saveRefreshToken( tempTable2.refresh_token, tempTable2.user_id )
								myInfo = tempTable2
								lis({error = nil, isError = false, response = "logined"})
								m.isLoginedIn = true
								myInfo = tempTable2
							else
								lis({error = "request failed: "..event.response, isError = true, response = nil})
							end
						end, {headers = headers, body= json.encode({idToken= tempTable3.idToken})} )
					else
						lis({error = "request failed: "..ev.response, isError = true, response = nil})
					end
				end )
			else
				lis({error = "request failed: "..e.response, isError = true, response = nil})
			end
		end, {headers = headers, body= json.encode(body)} )
	end
	function m.signOut(lis)
	 	if (m.isLoginedIn == true) then
	 		if (doesFileExist(fileName, system.DocumentsDirectory) == true) then
				m.haveRefreshToken = false
	 			m.isLoginedIn = false
	 			myInfo = nil
	 			myInfo= {}
	 			lis({error = nil, isError = true, response = "account removed and sign outed out"})
	 			os.remove( system.pathForFile( fileName, system.DocumentsDirectory ) )
	 		end
	 	else
	 		lis({error = "you need to be logined in", isError = true, response = nil})
	 	end
	end
	function m.createAccount( email, password, lis, verfiyEmail, signinAfterCreate )
		local sendEmail = true
		local saveData =  true
		if (signinAfterCreate ~= nil and signinAfterCreate == false) then
			saveData = false
		end
		if (verfiyEmail ~= nil and verfiyEmail == false) then
			sendEmail = false
		end
		local headers = {}
		local body = {}
		body.email = email
		body.password = password
		body.returnSecureToken = true
		headers["Content-Type"] = "application/json"
		local socket = require "socket"
		local ipv6Test = true
		local socketTest1 = socket.udp6()
		socketTest1:setpeername( "google.com", 54613 )
		local testPeerIP = socketTest1:getsockname()
		if (testPeerIP == "::") then
			ipv6Test = false
		end
		local myIp = ""
		if (ipv6Test) then --
			myIp = testPeerIP
		else
			local socketTest2 = socket.udp4()
			socketTest2:setpeername( "google.com", 54613 )
			local testPeerIP2 = socketTest2:getsockname()
			myIp = testPeerIP2
		end
		network.request( "https://www.googleapis.com/identitytoolkit/v3/relyingparty/signupNewUser?key="..urlencode(m.myKey), "POST", function (e)
			if (e.status == 200) then
				local tempTable2
				local tempTable3 =json.decode(e.response)
				network.request( "https://securetoken.googleapis.com/v1/token?grant_type=refresh_token&refresh_token="..tempTable3.refreshToken.."&key="..urlencode(m.myKey), "POST", function ( e )
					if (e.status == 200) then
						tempTable2 =json.decode(e.response)
						if (saveData == true) then
							saveRefreshToken( tempTable2.refresh_token, tempTable2.user_id )
							myInfo = tempTable2
							m.isLoginedIn = true
						end
						if (sendEmail== true) then
							local headers2 = {}
							headers2["Content-Type"] = "application/json"
							network.request( "https://www.googleapis.com/identitytoolkit/v3/relyingparty/getOobConfirmationCode?key="..urlencode(m.myKey), "POST", function ( ev )
								if (ev.status == 200) then
									lis({error = nil, isError = false, response = "email sent"})
								else
									lis({error = "request failed", isError = true, response = nil})
								end
							end, {headers = headers2,body=json.encode({kind= "identitytoolkit#relyingparty",requestType = "VERIFY_EMAIL" ,email= email, challenge = "corona", captchaResp = "corona",userIp= myIp, newEmail = email, idToken= tempTable2.id_token}) } )
						else
							lis({error = nil, isError = false, response = "account made with email"})
						end
					else
						lis({error = "request failed", isError = true, response = nil})
					end
				end )
			else
				lis({error = "request failed", isError = true, response = nil})
			end
		end, {headers = headers, body= json.encode(body)} )
	end
	function m.resetPassword( email, lis )
		local headers = {}
		headers["Content-Type"] = "application/json"
		network.request( "https://www.googleapis.com/identitytoolkit/v3/relyingparty/getOobConfirmationCode?key="..urlencode(m.myKey), "POST", function ( e )
			if (e.status == 200) then
				lis({error = nil, isError = false, response = "password sent"})
			else
				lis({error = "request failed: "..e.response, isError = true, response = nil})
			end
		end, {headers= headers, body= json.encode({kind = "identitytoolkit#relyingparty", requestType = "PASSWORD_RESET", email = email})} )
	end
	function m.setAccountInfo( displayName, email, password, lis)
		if (m.isLoginedIn == true) then
			local headers = {}
			headers["Content-Type"] = "application/json"
			network.request( "https://www.googleapis.com/identitytoolkit/v3/relyingparty/setAccountInfo?key="..urlencode(m.myKey), "POST", function ( e )
				if (e.status == 200) then
					lis({error = nil, isError = false, response = "info set"})
				else
					lis({error = "request failed: "..e.response, isError = true, response = nil})
				end
			end, {headers= headers, body= json.encode({idToken = myInfo.id_token, displayName = displayName, email = email, password = password})} )
		else
			lis({error = "you need to be logined in", isError = true, response = nil})
		end
	end
	function m.uploadUserData( data,lis ) --user as database will update whole database
		if (m.isLoginedIn == true) then
			local headers = {}
			headers["Accept"] = "application/json"
			headers["Content-Type"] = "application/json"
			network.request( m.myUrl.."/_users/"..myInfo.user_id.."/.json?auth="..m.databaseSecret, "PUT", function ( e )
				if (e.status == 200) then
					lis({error = nil, isError = false, response = "Data sent:"..e.response})
				else
					lis({error = "request failed: "..e.response, isError = true, response = nil})
				end
			end, {headers = headers, body= json.encode(data)} )
		else
			lis({error = "you need to be logined in", isError = true, response = nil})
		end
	end
	function m.deleteUserData( lis ) --user as database will update whole database
		if (m.isLoginedIn == true) then
			local headers = {}
			headers["Accept"] = "application/json"
			headers["Content-Type"] = "application/json"
			network.request( m.myUrl.."/_users/"..myInfo.user_id.."/.json?auth="..m.databaseSecret, "DELETE", function ( e )
				if (e.status == 200) then
					lis({error = nil, isError = false, response = "User info deleted:"..e.response})
				else
					lis({error = "request failed: "..e.response, isError = true, response = nil})
				end
			end, {headers = headers} )
		else
			lis({error = "you need to be logined in", isError = true, response = nil})
		end
	end
	function m.updateUserData( data,lis ) --user as database will update whole database
		if (m.isLoginedIn == true) then
			local headers = {}
			headers["Accept"] = "application/json"
			headers["Content-Type"] = "application/json"
			headers["X-HTTP-Method-Override"] = "PATCH"
			network.request( m.myUrl.."/_users/"..myInfo.user_id.."/.json?auth="..m.databaseSecret, "POST", function ( e )
				if (e.status == 200) then
					print( e.response )
					lis({error = nil, isError = false, response = "Data updated:"..e.response})
				else
					lis({error = "request failed: "..e.response, isError = true, response = nil})
				end
			end, {headers = headers, body= json.encode(data)} )
		else
			lis({error = "you need to be logined in", isError = true, response = nil})
		end
	end
	function m.getUserData( lis )
		if (m.isLoginedIn == true) then
			network.request( m.myUrl.."/_users/"..myInfo.user_id.."/.json?auth="..m.databaseSecret, "GET", function ( e )
				if (e.status == 200) then
					lis({error = nil, isError = false, response = e.response})
				else
					lis({error = "request failed: "..e.response, isError = true, response = nil})
				end
			end )
		else
			lis({error = "you need to be logined in", isError = true, response = nil})
		end
	end
	function m.getAccountInfo(lis)
		if (m.isLoginedIn == true) then
			local headers = {}
			headers["Content-Type"] = "application/json"
			network.request( "https://www.googleapis.com/identitytoolkit/v3/relyingparty/getAccountInfo?key="..urlencode(m.myKey), "POST", function ( e )
				if (e.status == 200) then
					lis({error = nil, isError = false, response = json.decode(e.response)})
				else
					lis({error = "request failed: "..e.response, isError = true, response = nil})
				end
			end, {headers= headers, body= json.encode({idToken = myInfo.id_token})} )
		else
			lis({error = "you need to be logined in", isError = true, response = nil})
		end
	end
	function m.deleteAccount(lis)
	 	if (m.isLoginedIn == true) then
	 		if (doesFileExist(fileName, system.DocumentsDirectory) == true) then
	 			m.deleteUserData( function ( ev )
	 				if (not ev.error) then
			 			local headers2 = {}
						headers2["Content-Type"] = "application/json"
			 			network.request( "https://www.googleapis.com/identitytoolkit/v3/relyingparty/deleteAccount?key="..urlencode(m.myKey), "POST", function ( e )
			 				if (e.status == 200) then
								m.haveRefreshToken = false
					 			m.isLoginedIn = false
					 			myInfo = nil
					 			myInfo= {}
					 			lis({error = nil, isError = false, response = "account removed and sign outed out"})
					 			os.remove( system.pathForFile( fileName, system.DocumentsDirectory ) )
							else
								lis({error = "unable to delete: "..e,response, isError = true, response = nil})
							end
			 			end, {headers = headers2, body = json.encode({localId= myInfo.localId})} )
			 		else
			 			lis({error = "unable to delete", isError = true, response = nil})
			 		end
		 		end)
	 		end
	 	else
	 		lis({error = "you need to be logined in", isError = true, response = nil})
	 	end
	end
	function m.uploadData( path, data,lis )
		local headers = {}
		headers["Accept"] = "application/json"
		headers["Content-Type"] = "application/json"
		network.request( m.myUrl.."/"..path.."/.json?auth="..m.databaseSecret, "PUT", function ( e )
			if (e.status == 200) then
				lis({error = nil, isError = false, response = "Data upload :"..e.response})
			else
				lis({error = "request failed: "..e.response, isError = true, response = nil})
			end
		end, {headers = headers, body= json.encode(data)} )
	end
	function m.updateData( path, data,lis )
		local headers = {}
		headers["Accept"] = "application/json"
		headers["Content-Type"] = "application/json"
		headers["X-HTTP-Method-Override"] = "PATCH"
		network.request( m.myUrl.."/"..path.."/.json?auth="..m.databaseSecret, "POST", function ( e )
			if (e.status == 200) then
				lis({error = nil, isError = false, response = "Data updated :"..e.response})
			else
				lis({error = "request failed: "..e.response, isError = true, response = nil})
			end
		end, {headers = headers, body= json.encode(data)} )
	end
	function m.deleteData( path,lis )
		network.request( m.myUrl.."/"..path.."/.json?auth="..m.databaseSecret, "DELETE", function ( e )
			if (e.status == 200) then
				lis({error = nil, isError = false, response = "Data deleted :"..e.response})
			else
				lis({error = "request failed: "..e.response, isError = true, response = nil})
			end
		end )
	end
	function m.getData( path,lis )
		network.request( m.myUrl.."/"..path.."/.json?auth="..m.databaseSecret, "GET", function ( e )
			if (e.status == 200) then
				lis({error = nil, isError = false, response = e.response})
			else
				lis({error = "request failed: "..e.response, isError = true, response = nil})
			end
		end )
	end
	--[[ not working
	function m.sendMessage( token, message, title, data,lis )
		local headers = {}
		headers["Content-Type"] = "application/json"
		headers["Authorization"] = "key="..m.myKey
		local data ={notification_key = token, notification = {text = message, title = title}, data = data}
		network.request( "https://fcm.googleapis.com/fcm/send", "POST", function ( e )
			print(json.encode(e))
			if (e.status == 200) then
				lis({error = nil, isError = false, response = e.response})
			else
				lis({error = "request failed", isError = true, response = nil})
			end
		end, {headers = headers, body= json.encode(data)} )
	end
	]]--
	function m.encodeFile( filename,dir )
		local base64 = require("plugin.firebase.base64")
		local myDir = system.ResourceDirectory
		if (dir) then
			myDir = dir
		end
		local path = system.pathForFile( filename, myDir )
		local fileHandle = io.open( path, "rb" )
		local tempString=base64.encode(fileHandle:read( "*a" ))
		local tempTable = filename:split("%.")
		local tempTable2 = tempTable[1]:split("/")
		local tempString3 = ""
		if (tempTable2 and tempTable2[1]) then
			tempString3= tempTable2[#tempTable2]
		else
			tempString3= tempTable[1]
		end
		local tempString2 = tempString.."_"..tempString3.."_"..tempTable[2]
		return tempString2
	end
	function m.decodeFile( txt, dir )
		local base64 = require("plugin.firebase.base64")
		local myDir = system.DocumentsDirectory
		if (dir) then
			myDir = dir
		end
		local tempTable= txt:split("_")
		local tempString2 = ""
		for i=1,#tempTable-2 do
			tempString2 = tempString2..tempTable[i]
		end
		local path
		local file, errorString
		if (path) then
			path = system.pathForFile( path2.."/"..tempTable[#tempTable-1].."."..tempTable[#tempTable], myDir )
			file, errorString= io.open( path, "w" )
		else
			path = system.pathForFile( tempTable[#tempTable-1].."."..tempTable[#tempTable], myDir)
			file, errorString= io.open( path, "w" )
		end
		if not file then
		else
		    -- Write data to file
		    file:write( base64.decode(tempString2) )
		    -- Close the file handle
		    io.close( file )
		end
		return tempTable[#tempTable-1].."."..tempTable[#tempTable], dir
	end
--else
--	error( "This is a beta, which only works in simulator, please get the full plugin when it becomes available" )
--end
return m