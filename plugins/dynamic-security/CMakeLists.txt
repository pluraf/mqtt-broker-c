if (CJSON_FOUND AND WITH_TLS)
	add_definitions("-DWITH_CJSON")

	set( CLIENT_INC ${mosquitto_SOURCE_DIR} ${mosquitto_SOURCE_DIR}/include
		${mosquitto_SOURCE_DIR}/jwt
		${STDBOOL_H_PATH} ${STDINT_H_PATH} ${PTHREAD_INCLUDE_DIR}
		${OPENSSL_INCLUDE_DIR} ${mosquitto_SOURCE_DIR}/deps
		${mosquitto_SOURCE_DIR}/src
		${CJSON_INCLUDE_DIRS} )

	set( CLIENT_DIR ${mosquitto_BINARY_DIR}/lib ${CJSON_DIR})

	include_directories(${CLIENT_INC})
	link_directories(${CLIENT_DIR} ${mosquitto_SOURCE_DIR})

	add_library(mosquitto_dynamic_security MODULE
		acl.c
		auth.c
		channels.c
		channellist.c
		dynamic_security.h
		groups.c
		grouplist.c
		json_help.c
		json_help.h
		plugin.c
		roles.c
		rolelist.c
		sub_matches_sub.c
		../../jwt/jwt.c
		../../jwt/jwt_helpers.c
		../../jwt/crypto/ecc-light-certificate/ecdsa.c
		../../jwt/crypto/ecc-light-certificate/ecc.c
		../../jwt/crypto/ecc-light-certificate/nn.c
		../../jwt/crypto/curve-params/secp256r1.c
		../../jwt/crypto/sha2/sha2.c
		../../jwt/base64/base64.c
		)

	set_target_properties(mosquitto_dynamic_security PROPERTIES
		POSITION_INDEPENDENT_CODE 1
	)
	set_target_properties(mosquitto_dynamic_security PROPERTIES PREFIX "")

	target_link_libraries(mosquitto_dynamic_security ${CJSON_LIBRARIES} ${OPENSSL_LIBRARIES})
	if(WIN32)
		target_link_libraries(mosquitto_dynamic_security mosquitto)
		install(TARGETS mosquitto_dynamic_security
			DESTINATION "${CMAKE_INSTALL_BINDIR}")
	else()
		install(TARGETS mosquitto_dynamic_security
			RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
			LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
	endif()

endif()
