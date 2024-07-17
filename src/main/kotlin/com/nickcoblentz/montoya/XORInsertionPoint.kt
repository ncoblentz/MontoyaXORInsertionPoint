package com.nickcoblentz.montoya

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointProvider
import com.nickcoblentz.montoya.MontoyaLogger
import java.util.regex.Pattern


class XORInsertionPoint : BurpExtension, AuditInsertionPointProvider {
    private val PluginName = "XOR Insertion Point"
    private lateinit var  Logger : MontoyaLogger
    private lateinit var Api : MontoyaApi
    val Base64Pattern: Pattern = Pattern.compile("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
    val ParameterTypesToMatch = listOf(HttpParameterType.URL,HttpParameterType.BODY,HttpParameterType.JSON)
    val ParameterTypesToURLDecode = listOf(HttpParameterType.URL,HttpParameterType.BODY)


    override fun initialize(api: MontoyaApi?) {
        if (api == null) {
            return
        }
        Api=api
        Logger = MontoyaLogger(api,MontoyaLogger.DebugLogLevel)

        Logger.debugLog( "Plugin Starting...")

        api.extension().setName(PluginName)
        api.scanner().registerInsertionPointProvider(this)

        Logger.debugLog( "Finished")

/*        Logger.debugLog("Test")
        val payload = "*)(!(objectClass=*)";

        payload?.let {
            val myPayload = encode(payload.toString())
            val urlEncodedmyPayload = Api.utilities().urlUtils().encode(myPayload)
            Logger.debugLog("Test case validation: \n\tOriginal Payload: ${payload.toString()}\n\t Xored, base64: $myPayload\n\tURL Encoded: $urlEncodedmyPayload\n\tExpected: Xl1cVVwbFh4RFw== -> %58%6c%31%63%56%56%77%62%46%68%34%52%46%77%3d%3d")

        }

        Logger.debugLog("End Test")*/
    }

    override fun provideInsertionPoints(httpRequestResponse: HttpRequestResponse?): MutableList<AuditInsertionPoint> {
        if(httpRequestResponse == null)
            return mutableListOf()
        val parameters = httpRequestResponse.request().parameters()

        val insertionPoints = parameters.filter {
            var value =it.value()
            if(it.type() in ParameterTypesToURLDecode)
                value=Api.utilities().urlUtils().decode(value)

            val matches = it.type() in ParameterTypesToMatch && it.value()!=null && it.value().trim().isNotEmpty() && Base64Pattern.matcher(value).matches()
            Logger.debugLog("${it.name()} (${it.type()}) = $value matches? $matches")
            matches
            /*when(it.type()) {
            HttpParameterType.URL -> Base64Pattern.matcher(Api.utilities().urlUtils().decode(it.value())).matches()
            HttpParameterType.BODY -> Base64Pattern.matcher(Api.utilities().urlUtils().decode(it.value())).matches()
            else -> Base64Pattern.matcher(it.value()).matches()
        }*/
        }.map {
            XORAuditInsertionPoint(Api, httpRequestResponse, it)
        }.toMutableList()

        Logger.debugLog("Insertion Points Returned:")
        for(insertionPoint in insertionPoints)
        {
            Logger.debugLog("\t${insertionPoint.parsedHttpParameter.name()}")
        }
        return (insertionPoints as MutableList<AuditInsertionPoint>)
    }
}