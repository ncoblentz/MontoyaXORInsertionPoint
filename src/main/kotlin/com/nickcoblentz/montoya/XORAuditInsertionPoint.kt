package com.nickcoblentz.montoya

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray
import burp.api.montoya.core.Range
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.params.HttpParameter.parameter
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint
import com.nickcoblentz.montoya.MontoyaLogger


class XORAuditInsertionPoint(private val Api: MontoyaApi, private val httpRequestResponse: HttpRequestResponse, val parsedHttpParameter: ParsedHttpParameter) : AuditInsertionPoint {

    private var Logger : MontoyaLogger = MontoyaLogger(Api,MontoyaLogger.DebugLogLevel)

    private val ParameterTypesToURLDecode = listOf(HttpParameterType.URL, HttpParameterType.BODY)

    override fun name(): String {
        return "Base64 Encoded, XORed"
    }

    override fun baseValue(): String {
        return when(parsedHttpParameter.type()) {
            in ParameterTypesToURLDecode -> decode(Api.utilities().urlUtils().decode(parsedHttpParameter.value()))
            else -> decode(parsedHttpParameter.value())
        }


    }

    override fun buildHttpRequestWithPayload(payload: ByteArray?): HttpRequest {
        payload?.let {
            var myPayload = encode(payload.toString())
            if(parsedHttpParameter.type() in ParameterTypesToURLDecode)
                myPayload = Api.utilities().urlUtils().encode(myPayload)
            Logger.debugLog("${parsedHttpParameter.name()} (${parsedHttpParameter.type()}) = ${parsedHttpParameter.value()} -> \n\tOriginal Payload: ${payload.toString()}\n\t Encoded: $myPayload")
            val updatedParameter = parameter(parsedHttpParameter.name(), myPayload, parsedHttpParameter.type())
            return httpRequestResponse.request().withUpdatedParameters(updatedParameter)
        }
        Logger.debugLog("Something went wrong and no payload was created")
        return httpRequestResponse.request()
    }

    override fun issueHighlights(payload: ByteArray?): MutableList<Range> {
        return mutableListOf()
    }

    private fun xorTransform(value : String) : String {
        return value.toCharArray().map { (it.code xor 0x74).toChar() }.joinToString("")
    }

    private fun decode(value: String) : String {
        return xorTransform(Api.utilities().base64Utils().decode(value).toString());
    }

    private fun encode(value: String) : String {
        return Api.utilities().base64Utils().encodeToString(xorTransform(value));
    }
}