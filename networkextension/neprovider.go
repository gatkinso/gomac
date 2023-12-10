/*
 * This file declares the NEProvider API. The NEProvider API declares the base class for Network Extension service providers.
 *
 * This API is part of NetworkExtension.framework
 */
package networkextension

/*
 * NEProviderStopReason
 * Provider stop reasons
 */
type NEProviderStopReason int

const (
	NEProviderStopReasonNone NEProviderStopReason = iota
	NEProviderStopReasonUserInitiated
	NEProviderStopReasonProviderFailed
	NEProviderStopReasonNoNetworkAvailable
	NEProviderStopReasonUnrecoverableNetworkChange
	NEProviderStopReasonProviderDisabled
	NEProviderStopReasonAuthenticationCanceled
	NEProviderStopReasonConfigurationFailed
	NEProviderStopReasonIdleTimeout
	NEProviderStopReasonConfigurationDisabled
	NEProviderStopReasonConfigurationRemoved
	NEProviderStopReasonSuperceded
	NEProviderStopReasonUserLogout
	NEProviderStopReasonUserSwitch
	NEProviderStopReasonConnectionFailed
	NEProviderStopReasonSleep
	NEProviderStopReasonAppUpdate
)

type NWEndpoint struct {
	// Define NWEndpoint properties
}

type NWHostEndpoint struct {
	// Define NWHostEndpoint properties
}

type NWPath struct {
	// Define NWPath properties
}

type NWTCPConnection struct {
	// Define NWTCPConnection properties
}

type NWTLSParameters struct {
	// Define NWTLSParameters properties
}

type NWUDPSession struct {
	// Define NWUDPSession properties
}

/*
 * NEProvider
 * The NEProvider class declares the programmatic interface that is common for all Network Extension providers.
 *
 * See the sub classes of NEProvider for more details. Developers of Network Extension providers should create sub classes of the sub classes of NEProvider.
 *
 * Instances of this class are thread safe.
 */
type NEProvider struct {
	// Define NEProvider properties
}

/*
 * sleepWithCompletionHandler:
 * This function is called by the framework when the system is about to go to sleep. Subclass developers can override this method to implement custom behavior such as closing connections or pausing some network activity.
 * completionHandler When the method is finished handling the sleep event it must execute this completion handler.
 */
func (p *NEProvider) SleepWithCompletionHandler(completionHandler func()) {
	// Implement sleepWithCompletionHandler method
}

/*
 * wake
 * This function is called by the framework immediately after the system wakes up from sleep. Subclass developers can override this method to implement custom behavior such as re-establishing connections or resuming some network activity.
 */
func (p *NEProvider) Wake() {
	// Implement wake method
}

/*
 * createTCPConnectionToEndpoint:enableTLS:TLSParameters:delegate:
 * This function can be called by subclass implementations to create a TCP connection to a given network endpoint. This function should not be overridden by subclasses.
 * remoteEndpoint An NWEndpoint object that specifies the remote network endpoint to connect to.
 * enableTLS A flag indicating if a TLS session should be negotiated on the connection.
 * TLSParameters A set of optional TLS parameters. Only valid if enableTLS is YES. If TLSParameters is nil, the default system parameters will be used for TLS negotiation.
 * delegate An object to use as the connections delegate. This object should conform to the NWTCPConnectionAuthenticationDelegate protocol.
 * @return An NWTCPConnection object.
 */
func (p *NEProvider) CreateTCPConnectionToEndpoint(remoteEndpoint *NWEndpoint, enableTLS bool, TLSParameters *NWTLSParameters, delegate interface{}) *NWTCPConnection {
	// Implement createTCPConnectionToEndpoint method
	return nil
}

/*
 * createUDPSessionToEndpoint:fromEndpoint:
 * This function can be called by subclass implementations to create a UDP session between a local network endpoint and a remote network endpoint. This function should not be overridden by subclasses.
 * remoteEndpoint An NWEndpoint object that specifies the remote endpoint to which UDP datagrams will be sent by the UDP session.
 * localEndpoint An NWHostEndpoint object that specifies the local IP address endpoint to use as the source endpoint of the UDP session.
 * @return An NWUDPSession object.
 */
func (p *NEProvider) CreateUDPSessionToEndpoint(remoteEndpoint *NWEndpoint, localEndpoint *NWHostEndpoint) *NWUDPSession {
	// Implement createUDPSessionToEndpoint method
	return nil
}

/*
 * displayMessage:completionHandler:
 * This method can be called by subclass implementations to display a message to the user.
 * message The message to be displayed.
 * completionHandler A block that is executed when the user acknowledges the message. If this method is called on a NEFilterDataProvider instance or the message cannot be displayed, then the completion handler block will be executed immediately with success parameter set to NO. If the message was successfully displayed to the user, then the completion handler block is executed with the success parameter set to YES when the user dismisses the message.
 */
func (p *NEProvider) DisplayMessage(message string, completionHandler func(bool)) {
	// Implement displayMessage method
}

/*
 * startSystemExtensionMode
 * Start the Network Extension machinery in a system extension (.system bundle). This class method will cause the calling system extension to start handling
 *    requests from nesessionmanager to instantiate appropriate NEProvider sub-class instances. The system extension must declare a mapping of Network Extension extension points to
 *    NEProvider sub-class instances in its Info.plist:
 *        Key: NetworkExtension
 *        Type: Dictionary containing information about the NetworkExtension capabilities of the system extension.
 *
 *            Key: NEProviderClasses
 *            Type: Dictionary mapping NetworkExtension extension point identifiers to NEProvider sub-classes
 *
 *    Example:
 *
 *        <key>NetworkExtension</key>
 *        <dict>
 *            <key>NEProviderClasses</key>
 *            <dict>
 *                <key>com.apple.networkextension.app-proxy</key>
 *                <string>$(PRODUCT_MODULE_NAME).AppProxyProvider</string>
 *                <key>com.apple.networkextension.filter-data</key>
 *                <string>$(PRODUCT_MODULE_NAME).FilterDataProvider</string>
 *            </dict>
 *        </dict>
 *
 *    This method should be called as early as possible after the system extension starts.
 */
func (p *NEProvider) StartSystemExtensionMode() {
	// Implement startSystemExtensionMode method
}

/*
 * defaultPath
 * The current default path for connections created by the provider. Use KVO to watch for network changes.
 */
func (p *NEProvider) GetDefaultPath() *NWPath {
	// Implement getDefaultPath method
	return nil
}
