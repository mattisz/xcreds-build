//
//  FreeIPAUser.swift
//  nomad-ad
//
//  Rewritten for FreeIPA / 389 Directory Server + MIT Kerberos schema
//  (originally ADUser.swift, Created by Joel Rennich on 9/9/17.)
//  Copyright © 2018 Orchard & Grove Inc. All rights reserved.
//

import Foundation
//import NoMADPRIVATE

public protocol NoMADUserSession {
    func getKerberosTicket(principal: String?, completion: @escaping (KerberosTicketResult) -> Void)
    func authenticate(authTestOnly: Bool)
//    func changePassword(oldPassword: String, newPassword: String, completion: @escaping (String?) -> Void)
    func changeKerberosPassword() throws
    func userInfo()
    var delegate: NoMADUserSessionDelegate? { get set }
    var state: NoMADSessionState { get }
}

public typealias KerberosTicketResult = Result<ADUserRecord, NoMADSessionError>

public protocol NoMADUserSessionDelegate: AnyObject {
    func NoMADAuthenticationSucceeded()
    func NoMADAuthenticationFailed(error: NoMADSessionError, description: String)
    func NoMADUserInformation(user: ADUserRecord)
}

public enum NoMADSessionState {
    case success
    case offDomain
    case siteFailure       // kept for protocol compatibility; unused under FreeIPA (no site concept)
    case networkLookup
    case passwordChangeRequired
    case unset
    case lookupError
    case kerbError
}

public enum NoMADSessionError: String, Error {
    case OffDomain
    case UnAuthenticated
    case SiteError
    case StateError
    case AuthenticationFailure
    case KerbError
    case PasswordExpired = "Password has expired"
    case UnknownPrincipal
    case wrongRealm = "Wrong realm"
    case AccountLocked
}

/// LDAP backend type. FreeIPA is the primary target (389 Directory Server +
/// MIT Kerberos schema); OD is retained for generic Open Directory/389-ds
/// servers that don't carry the krb5kdc-ldap schema.
public enum LDAPType {
    case AD
    case OD
}

public enum GSSErrorKey : String {

    case mechanismKey = "kGSSMechanism"
    case mechanismOIDKey = "kGSSMechanismOID"
    case majorErrorCodeKey = "kGSSMajorErrorCode"
    case minorErrorCodeKey = "kGSSMinorErrorCode"
    case descriptionKey = "NSDescription"

}
public struct GSSError {
    var mechanism:String
    var mechanismOID:String
    var majorErrorCode:Int
    var minorErrorCode:UInt
    var description:String

}
public struct NoMADLDAPServer {
    var host: String
    var status: String
    var priority: Int
    var weight: Int
    var timeStamp: Date
}

// MARK: Start of public class

/// A general purpose class that is the main entrypoint for interactions with FreeIPA / MIT Kerberos.
@available(macOS, deprecated: 11)
public class NoMADSession: NSObject {

    public var state: NoMADSessionState = .offDomain          // current state of affairs
    weak public var delegate: NoMADUserSessionDelegate?       // delegate
    public var defaultNamingContext: String = ""              // current default naming context
    private var hosts = [NoMADLDAPServer]()                   // list of LDAP servers
    private var resolver = DNSResolver()                      // DNS resolver object
    private var maxSSF = ""                                   // current security level in place for LDAP lookups
    private var URIPrefix = "ldap://"                         // LDAP or LDAPS
    private var current = 0                                   // current LDAP server from hosts
    public var home = ""                                      // current active user home
    public var ldapServers: [String]?                         // static LDAP servers to use instead of looking up via DNS records

    // Base configuration prefs
    // change these on the object as needed

    public var domain: String = ""                  // current LDAP Domain - can be set with init
    public var kerberosRealm: String = ""           // Kerberos realm
    public var createKerbPrefs: Bool = true         // Determines if skeleton Kerb prefs should be set

    public var siteIgnore: Bool = true
    public var siteForce: Bool = false              // force a site?
    public var siteForceSite: String = ""           // what site to force

    public var ldaptype: LDAPType = .AD        // Type of LDAP server
    public var port: Int = 389                      // LDAP port typically either 389 or 636
    public var anonymous: Bool = false              // Anonymous LDAP lookup
    public var useSSL: Bool = false                 // Toggle SSL

    public var recursiveGroupLookup : Bool = false  // Toggle recursive group lookup

    // User

    public var userPrincipal: String = ""           // Full user principal
    public var userPrincipalShort: String = ""      // user shortname (uid) - necessary for any lookups to happen
    public var userRecord: ADUserRecord? = nil      // ADUserRecordObject containing all user information
    public var userPass: String = ""                // for auth
    public var oldPass: String = ""                 // for password changes
    public var newPass: String = ""                 // for password changes
    public var customAttributes : [String]?

    // conv. init with domain and user

    /// Convenience initializer to create a `NoMADSession` with the given domain, username, and `LDAPType`
    ///
    /// - Parameters:
    ///   - domain: The IPA domain for the user.
    ///   - user: The user's name. Either the bare `uid`, or the full Kerberos principal (`uid@REALM`) are accepted.
    ///   - type: The type of LDAP connection. Defaults to FreeIPA.
    public init(domain: String, user: String, type: LDAPType = .AD) {

        // configuration parts
        self.domain = domain
        self.ldaptype = type

        // check for the REALM
        if user.contains("@") {
            self.userPrincipalShort = user.components(separatedBy: "@").first!
            self.kerberosRealm = user.components(separatedBy: "@").last!.uppercased()
            self.userPrincipal = user
        } else {
            self.userPrincipalShort = user
            self.kerberosRealm = domain.uppercased()
            self.userPrincipal = user + "@\(self.kerberosRealm)"
        }

    }

    // MARK: conv functions

    // Return the current server

    var currentServer: String {
        TCSLogWithMark("Computed currentServer accessed in state: \(String(describing: state))")

        if state != .offDomain {

            if hosts.isEmpty {
                TCSLogWithMark("Make sure we have LDAP servers")
                getHosts(domain)
            }
            TCSLogWithMark("Lookup the current LDAP host in: \(String(describing: hosts))")

            return hosts[current].host
        } else {
            return ""
        }
    }

    // MARK: DNS Main
    //
    // NOTE: FreeIPA has no concept of AD "sites" - DNS SRV discovery is a
    // flat list of LDAP servers for the domain (_ldap._tcp.<domain>) and
    // Kerberos servers (_kerberos._tcp.<domain> / _kpasswd._tcp.<domain>).
    // The old AD site-aware "_sites" SRV lookups and the NETLOGON LDAP ping
    // used to discover the closest site have been removed entirely - they
    // do not apply to FreeIPA/389-DS + MIT Kerberos.

    fileprivate func parseSRVReply(_ results: inout [String]) {
        if (self.resolver.error == nil) {
            TCSLogWithMark("Did Receive Query Result: " + self.resolver.queryResults.description)
            TCSLogWithMark("Copy \(resolver.queryResults.count) result to records")
            let records = self.resolver.queryResults as! [[String:AnyObject]]
            TCSLogWithMark("records dict ready: " + records.debugDescription)
            for record: Dictionary in records {
                TCSLogWithMark("Adding: \(String(describing: record["target"]))")
                let host = record["target"] as! String
                TCSLogWithMark("Created host: " + host)
                results.append(host)
                TCSLogWithMark("Added host to results: \(String(describing: results))")
            }
        } else {
            TCSLogWithMark("Query Error: " + self.resolver.error.localizedDescription)
        }
    }

    func getSRVRecords(_ domain: String, srv_type: String="_ldap._tcp.") -> [String] {
        self.resolver.queryType = "SRV"

        self.resolver.queryValue = srv_type + domain

        var results = [String]()

        TCSLogWithMark("Starting DNS query for SRV records.")

        self.resolver.startQuery()

        while ( !self.resolver.finished ) {
            RunLoop.current.run(mode: RunLoop.Mode.default, before: Date.distantFuture)
        }

        parseSRVReply(&results)
        TCSLogWithMark("Returning results: \(String(describing: results))")
        return results
    }

    fileprivate func parseHostsReply() {
        if (self.resolver.error == nil) {
            TCSLogWithMark("Did Receive Query Result: " + self.resolver.queryResults.description)

            var newHosts = [NoMADLDAPServer]()
            let records = self.resolver.queryResults as! [[String:AnyObject]]
            for record: Dictionary in records {
                let host = record["target"] as! String
                let priority = record["priority"] as! Int
                let weight = record["weight"] as! Int
                // let port = record["port"] as! Int
                let currentServer = NoMADLDAPServer(host: host, status: "found", priority: priority, weight: weight, timeStamp: Date())
                newHosts.append(currentServer)
            }

            // now to sort them

            let fallbackHosts = self.hosts

            self.hosts = newHosts.sorted { (x, y) -> Bool in
                return ( x.priority <= y.priority )
            }

            // add back in the previously known-good servers in case the new set has gone bust
            // credit to @mosen for this brilliant idea

            self.hosts.append(contentsOf: fallbackHosts)
            state = .success

        } else {
            TCSLogWithMark("Query Error: " + self.resolver.error.localizedDescription)
            state = .offDomain
            self.hosts.removeAll()
        }
    }

    fileprivate func getHosts(_ domain: String ) {

        // check to see if we have static hosts

        if let servers = ldapServers {

            TCSLogWithMark("Using static LDAP server list.")
            var newHosts = [NoMADLDAPServer]()
            for server in servers {

                let host = server
                let priority = 100
                let weight = 100
                // let port = record["port"] as! Int
                let currentServer = NoMADLDAPServer(host: host, status: "found", priority: priority, weight: weight, timeStamp: Date())
                newHosts.append(currentServer)

                self.hosts = newHosts.sorted { (x, y) -> Bool in
                    return ( x.priority <= y.priority )
                }
                state = .success

                return
            }

        }

        self.resolver.queryType = "SRV"
        self.resolver.queryValue = "_ldap._tcp." + domain

        // check for a query already running

        TCSLogWithMark("Starting DNS query for SRV records.")

        self.resolver.startQuery()

        while ( !self.resolver.finished ) {
            RunLoop.current.run(mode: RunLoop.Mode.default, before: Date.distantFuture)
            TCSLogWithMark("Waiting for DNS query to return.")
        }

        parseHostsReply()
    }

    fileprivate func testHosts() {
        if state == .success {
            for i in 0...( hosts.count - 1) {
                if hosts[i].status != "dead" {
                    myLogger.logit(.info, message:"Trying host: " + hosts[i].host)

                    // socket test first - this could be falsely negative
                    // also note that this needs to return stderr

                    let mySocketResult = cliTask("/usr/bin/nc -G 5 -z " + hosts[i].host + " " + String(port))

                    if mySocketResult.contains("succeeded!") {

                        // FreeIPA / 389-DS RootDSE always exposes this as
                        // "namingContexts" regardless of ldaptype - there is
                        // no AD-style "defaultNamingContext" attribute here.
                        let attribute = "namingContexts"

                        var myLDAPResult = ""

                        if anonymous {
                            myLDAPResult = cliTask("/usr/bin/ldapsearch -N -LLL -x " + maxSSF + "-l 3 -s base -H " + URIPrefix + hosts[i].host + " " + String(port) + " " + attribute)
                        } else {
                            myLDAPResult = cliTask("/usr/bin/ldapsearch -N -LLL -Q " + maxSSF + "-l 3 -s base -H " + URIPrefix + hosts[i].host + " " + String(port) + " " + attribute)
                        }

                        if myLDAPResult != "" && !myLDAPResult.contains("GSSAPI Error") && !myLDAPResult.contains("Can't contact") {
                            let ldifResult = cleanLDIF(myLDAPResult)
                            if ( ldifResult.count > 0 ) {
                                defaultNamingContext = selectDomainNamingContext(getAttributeForSingleRecordFromCleanedLDIF(attribute, ldif: ldifResult))
                                hosts[i].status = "live"
                                hosts[i].timeStamp = Date()
                                myLogger.logit(.base, message:"Current LDAP Server is: " + hosts[i].host )
                                myLogger.logit(.base, message:"Current default naming context: " + defaultNamingContext )
                                current = i
                                break
                            }
                        }
                        // We didn't get an actual LDIF Result... so LDAP isn't working.
                        myLogger.logit(.info, message:"Server is dead by way of ldap test: " + hosts[i].host)
                        hosts[i].status = "dead"
                        hosts[i].timeStamp = Date()
                        break

                    } else {
                        myLogger.logit(.info, message:"Server is dead by way of socket test: " + hosts[i].host)
                        hosts[i].status = "dead"
                        hosts[i].timeStamp = Date()
                    }
                }
            }
        }

        guard ( hosts.count > 0 ) else {
            return
        }

        if hosts.last!.status == "dead" {
            myLogger.logit(.base, message: "All IPA servers are dead! You should really fix this.")
            state = .offDomain
        } else {
            state = .success
        }
    }

    // MARK: LDAP Retrieval

    func getLDAPInformation( _ attributes: [String], baseSearch: Bool=false, searchTerm: String="", test: Bool=true, overrideDefaultNamingContext: Bool=false) throws -> [[String:String]] {

        if test {
            guard testSocket(self.currentServer) else {
                throw NoMADSessionError.StateError
            }
        }

        if (overrideDefaultNamingContext == false) {
            if (defaultNamingContext == "") || (defaultNamingContext.contains("GSSAPI Error")) {
                testHosts()
            }
        }

        // TODO
        // ensure we're using the right kerberos credential cache
        //swapPrincipals(false)

        let command = "/usr/bin/ldapsearch"
        var arguments: [String] = [String]()
        arguments.append("-N")
        if anonymous {
            arguments.append("-x")
        } else {
            arguments.append("-Q")
        }
        arguments.append("-LLL")
        arguments.append("-o")
        arguments.append("nettimeout=1")
        arguments.append("-o")
        arguments.append("ldif-wrap=no")
        if baseSearch {
            arguments.append("-s")
            arguments.append("base")
        }
        if maxSSF != "" {
            arguments.append("-O")
            arguments.append("maxssf=0")
        }
        arguments.append("-H")
        arguments.append(URIPrefix + self.currentServer)
        arguments.append("-b")
        arguments.append(self.defaultNamingContext)
        if ( searchTerm != "") {
            arguments.append(searchTerm)
        }
        arguments.append(contentsOf: attributes)
        let ldapResult = cliTask(command, arguments: arguments)
        TCSLogWithMark("command: \(command) args: \(arguments)")
        if (ldapResult.contains("GSSAPI Error") || ldapResult.contains("Can't contact")) {
            throw NoMADSessionError.StateError
        }

        let myResult = cleanLDIF(ldapResult)

        // TODO
        //swapPrincipals(true)

        return myResult
    }

    fileprivate func cleanGroups(_ groupsTemp: String?, _ groups: inout [String]) {
        // clean up groups
        // FreeIPA groups are still returned as memberOf DNs like
        // "cn=admins,cn=groups,cn=accounts,dc=example,dc=com;cn=..." so the
        // CN-extraction logic is unchanged from the AD version.

        if groupsTemp != nil {
            let groupsArray = groupsTemp!.components(separatedBy: ";")
            for group in groupsArray {
                let a = group.components(separatedBy: ",")
                var b = a[0].replacingOccurrences(of: "CN=", with: "") as String
                b = b.replacingOccurrences(of: "cn=", with: "") as String

                if b != "" {
                    groups.append(b)
                }
            }
            myLogger.logit(.info, message: "You are a member of: " + groups.joined(separator: ", ") )
        }
    }

    fileprivate func lookupRecursiveGroups(_ dn: String, _ groupsTemp: inout String?) {
        // now to get recursive groups if asked
        //
        // FreeIPA / 389-DS ships its own recursive-membership matching rule
        // (1.3.6.1.4.1.42.2.27.9.1.4.1.501) under the in-memberOf / MemberOf
        // plugin's control - this replaces AD's
        // 1.2.840.113556.1.4.1941:= matching rule OID.

        if recursiveGroupLookup {
            let attributes = ["name"]
            let searchTerm = "(member:1.3.6.1.4.1.42.2.27.9.1.4.1.501:=" + dn.replacingOccurrences(of: "\\", with: "\\\\5c") + ")"
            if let ldifResult = try? getLDAPInformation(attributes, searchTerm: searchTerm) {
                groupsTemp = ""
                for item in ldifResult {
                    for components in item {
                        if components.key == "dn" {
                            groupsTemp?.append(components.value + ";")
                        }
                    }
                }
            }
        }
    }

    /// Parses Kerberos LDAP GeneralizedTime strings (e.g. "20260630120000Z"),
    /// used by krbLastPwdChange / krbPasswordExpiration, in place of the AD
    /// Windows FILETIME math this used to require.
    fileprivate func parseKerberosTimestamp(_ raw: String?) -> Date? {
        guard let raw = raw, raw != "" else { return nil }
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMddHHmmss'Z'"
        formatter.timeZone = TimeZone(identifier: "UTC")
        return formatter.date(from: raw)
    }

    fileprivate func parseExpirationDate(_ krbPasswordExpirationRaw: String?, _ passwordAging: inout Bool, _ userPasswordExpireDate: inout Date, _ accountLocked: String, _ serverPasswordExpirationDefault: inout Double, _ tempPasswordSetDate: Date) {

        if let expireDate = parseKerberosTimestamp(krbPasswordExpirationRaw) {
            // krbPasswordExpiration is set directly on the user entry by the
            // KDC according to whatever krbPwdPolicy applies, so unlike AD
            // there's no separate "never expires" UAC bit to check - a
            // missing/unparsable value just means no expiration is enforced.
            passwordAging = true
            userPasswordExpireDate = expireDate
        } else {
            // No krbPasswordExpiration on the entry at all - either no
            // password policy applies, or the account predates one.
            // Fall back to the domain's global password policy
            // (cn=global_policy,cn=<REALM>,cn=kerberos,<basedn>) for
            // krbMaxPwdLife (seconds) to compute an expiration relative to
            // krbLastPwdChange.
            var passwordExpirationLengthSeconds: String

            let tempDefault = defaultNamingContext
            defaultNamingContext = "cn=global_policy,cn=\(kerberosRealm),cn=kerberos," + defaultNamingContext

            if let ldifResult = try? getLDAPInformation(["krbMaxPwdLife"], baseSearch: true) {
                passwordExpirationLengthSeconds = getAttributeForSingleRecordFromCleanedLDIF("krbMaxPwdLife", ldif: ldifResult)
            } else {
                passwordExpirationLengthSeconds = ""
            }

            defaultNamingContext = tempDefault

            if passwordExpirationLengthSeconds == "" || passwordExpirationLengthSeconds == "0" {
                // no max password life configured - password does not expire
                serverPasswordExpirationDefault = Double(0)
                passwordAging = false
            } else {
                serverPasswordExpirationDefault = Double(passwordExpirationLengthSeconds) ?? 0
                passwordAging = serverPasswordExpirationDefault > 0
            }
            userPasswordExpireDate = tempPasswordSetDate.addingTimeInterval(serverPasswordExpirationDefault)
        }
    }

    fileprivate func extractedFunc(_ attributes: [String], _ searchTerm: String) {
        if let ldifResult = try? getLDAPInformation(attributes, searchTerm: searchTerm) {
            let ldapResult = getAttributesForSingleRecordFromCleanedLDIF(attributes, ldif: ldifResult)
            _ = ldapResult["homeDirectory"] ?? ""
            _ = ldapResult["displayName"] ?? ""
            _ = ldapResult["memberOf"]
            _ = ldapResult["mail"] ?? ""
            _ = ldapResult["uid"] ?? ""
        } else {
            myLogger.logit(.base, message: "Unable to find user.")
        }
    }

    func getUserInformation() -> Bool {

        // some setup

        var passwordAging = true
        var tempPasswordSetDate = Date()
        var serverPasswordExpirationDefault = 0.0
        var userPasswordExpireDate = Date()
        var groups = [String]()
        var userHome = ""

        if ldaptype == .AD {
            // FreeIPA user entries combine posixAccount + krbPrincipalAux
            // (+ inetOrgPerson) objectClasses, so the relevant attributes are
            // uid, krbPrincipalName, krbLastPwdChange, krbPasswordExpiration,
            // nsAccountLock, krbPwdPolicyReference, etc. rather than the AD
            // sAMAccountName / pwdLastSet / userAccountControl / msDS-* set.
            var attributes = ["krbLastPwdChange", "krbPasswordExpiration", "nsAccountLock", "homeDirectory", "displayName", "memberOf", "mail", "krbPrincipalName", "dn", "givenName", "sn", "cn", "krbPwdPolicyReference"] // passwordSetDate, computedExpireDateRaw, accountLocked, userHomeTemp, userDisplayName, groupTemp

            if customAttributes?.count ?? 0 > 0 {
                attributes.append(contentsOf: customAttributes!)
            }

            let searchTerm = "(|(uid="+userPrincipalShort+")(krbPrincipalName="+userPrincipalShort+"@"+kerberosRealm+"))"

            // Scope this to the real accounts tree (cn=accounts,<basedn>),
            // not the whole domain suffix. FreeIPA's schema-compat plugin
            // (slapi-nis) publishes a shadow copy of every active user under
            // cn=users,cn=compat,<basedn> for legacy NIS/NSS lookups, right
            // alongside the authoritative entry under
            // cn=users,cn=accounts,<basedn>. Searching from the domain
            // suffix matches both and getUserInformation() (correctly)
            // bails out as "Multiple records found" rather than guess which
            // is real.
            let tempDefaultNamingContext = defaultNamingContext
            defaultNamingContext = "cn=accounts," + defaultNamingContext

            let ldifResultOrNil = try? getLDAPInformation(attributes, searchTerm: searchTerm, overrideDefaultNamingContext: true)

            defaultNamingContext = tempDefaultNamingContext

            if let ldifResult = ldifResultOrNil {
                if ldifResult.count>1 {

                    TCSLogWithMark("Multiple records found. exiting")
                    return false
                }
                else if ldifResult.count==0 {

                    TCSLogWithMark("no user records found. exiting")
                    return false
                }
                let ldapResult = getAttributesForSingleRecordFromCleanedLDIF(attributes, ldif: ldifResult)
                TCSLogWithMark(ldapResult.description)
                let passwordSetDate = ldapResult["krbLastPwdChange"]
                let krbPasswordExpirationRaw = ldapResult["krbPasswordExpiration"]
                let accountLocked = ldapResult["nsAccountLock"] ?? ""
                let userHomeTemp = ldapResult["homeDirectory"] ?? ""

                var userDisplayName = ldapResult["displayName"] ?? ""

                TCSLogWithMark("userDisplayName: \(userDisplayName)")
                if let mapKey = DefaultsOverride.standardOverride.object(forKey: PrefKeys.mapFullName.rawValue)  as? String, mapKey.count>0, let mapValue = ldapResult[mapKey]  {
                    userDisplayName=mapValue
                    TCSLogWithMark("userDisplayName: \(userDisplayName)")
                }

                TCSLogWithMark("userDisplayName: \(userDisplayName)")

                var firstName = ldapResult["givenName"] ?? ""

                if let mapKey = DefaultsOverride.standardOverride.object(forKey: PrefKeys.mapFirstName.rawValue)  as? String, mapKey.count>0, let mapValue = ldapResult[mapKey]  {
                    firstName=mapValue
                }
                var lastName = ldapResult["sn"] ?? ""

                if let mapKey = DefaultsOverride.standardOverride.object(forKey: PrefKeys.mapLastName.rawValue)  as? String, mapKey.count>0, let mapValue = ldapResult[mapKey]  {
                    lastName=mapValue
                }

                var shortName = userPrincipalShort

                if let mapKey = DefaultsOverride.standardOverride.object(forKey: PrefKeys.mapUserName.rawValue)  as? String, mapKey.count>0, let mapValue = ldapResult[mapKey]  {
                    shortName=mapValue
                }


                var groupsTemp = ldapResult["memberOf"]
                let userEmail = ldapResult["mail"] ?? ""
                let UPN = ldapResult["krbPrincipalName"] ?? ""
                let dn = ldapResult["dn"] ?? ""
                let cn = ldapResult["cn"] ?? ""
                let pwdPolicyRef = ldapResult["krbPwdPolicyReference"] ?? ""

                var customAttributeResults : [String:Any]?

                if customAttributes?.count ?? 0 > 0 {
                    var tempCustomAttr = [String:Any]()
                    for key in customAttributes! {
                        tempCustomAttr[key] = ldapResult[key] ?? ""
                    }
                    customAttributeResults = tempCustomAttr
                }

                if ldapResult.count == 0 {
                    // we didn't get a result
                }

                lookupRecursiveGroups(dn, &groupsTemp)

                if let parsedSetDate = parseKerberosTimestamp(passwordSetDate) {
                    tempPasswordSetDate = parsedSetDate
                }
                parseExpirationDate(krbPasswordExpirationRaw, &passwordAging, &userPasswordExpireDate, accountLocked, &serverPasswordExpirationDefault, tempPasswordSetDate)

                cleanGroups(groupsTemp, &groups)

                // clean up the home

                userHome = userHomeTemp.replacingOccurrences(of: "\\", with: "/")
                userHome = userHome.replacingOccurrences(of: " ", with: "%20")

                // pack up user record
                // Note: uacFlags / ntName have no FreeIPA equivalent. We surface
                // account-lock state via nsAccountLock instead and leave ntName
                // blank; passwordLength comes from the referenced krbPwdPolicy.
                TCSLogWithMark("userDisplayName: \(userDisplayName)")
                TCSLogWithMark("ldifResult: \(ldifResult.debugDescription)")
                userRecord = ADUserRecord(userPrincipal: userPrincipal,firstName: firstName, lastName: lastName, fullName: userDisplayName, shortName: shortName, upn: UPN, email: userEmail, groups: groups, homeDirectory: userHome, passwordSet: tempPasswordSetDate, passwordExpire: userPasswordExpireDate, uacFlags: accountLocked.uppercased() == "TRUE" ? 1 : 0, passwordAging: passwordAging, computedExireDate: userPasswordExpireDate, updatedLast: Date(), domain: domain, cn: cn, pso: pwdPolicyRef, passwordLength: getComplexity(pso: pwdPolicyRef), ntName: "", customAttributes: customAttributeResults, rawAttributes: ldifResult.first)

            } else {
                myLogger.logit(.base, message: "Unable to find user.")
            }

        } else {

            let attributes = [ "homeDirectory", "displayName", "memberOf", "mail", "uid"] // passwordSetDate, computedExpireDateRaw, accountLocked, userHomeTemp, userDisplayName, groupTemp

            let searchTerm = "uid=" + userPrincipalShort

            extractedFunc(attributes, searchTerm)
        }

        // pack up the user record
        return true
    }

    // MARK: LDAP cleanup functions

    fileprivate func cleanLDIF(_ ldif: String) -> [[String:String]] {
        //var myResult = [[String:String]]()

        var ldifLines: [String] = ldif.components(separatedBy: CharacterSet.newlines)

        var records = [[String:String]]()
        var record = [String:String]()
        var attributes = Set<String>()

        for var i in 0..<ldifLines.count {
            // save current lineIndex
            let lineIndex = i
            ldifLines[lineIndex] = ldifLines[lineIndex].trim()

            // skip version
            if i == 0 && ldifLines[lineIndex].hasPrefix("version") {
                continue
            }

            if !ldifLines[lineIndex].isEmpty {
                // fold lines

                while i+1 < ldifLines.count && ldifLines[i+1].hasPrefix(" ") {
                    ldifLines[lineIndex] += ldifLines[i+1].trim()
                    i += 1
                }
            } else {
                // end of record
                if (record.count > 0) {
                    records.append(record)
                }
                record = [String:String]()
            }

            // skip comment
            if ldifLines[lineIndex].hasPrefix("#") {
                continue
            }

            let attribute = ldifLines[lineIndex].split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
            if attribute.count == 2 {

                // Get the attribute name (before ;),
                // then add to attributes array if it doesn't exist.
                var attributeName = attribute[0].trim()
                if let index = attributeName.firstIndex(of: ";") {
                    attributeName = String(attributeName[..<index])
                }
                if !attributes.contains(attributeName) {
                    attributes.insert(attributeName)
                }

                // Get the attribute value.
                // Check if it is a URL (<), or base64 string (:)
                var attributeValue = attribute[1].trim()
                // If
                if attributeValue.hasPrefix("<") {
                    // url
                    attributeValue = attributeValue.substring(from: attributeValue.index(after: attributeValue.startIndex)).trim()
                } else if attributeValue.hasPrefix(":") {
                    // base64
                    let tempAttributeValue = attributeValue.substring(from: attributeValue.index(after: attributeValue.startIndex)).trim()
                    if (Data(base64Encoded: tempAttributeValue, options: NSData.Base64DecodingOptions.init(rawValue: 0)) != nil) {
                        //attributeValue = tempAttributeValue

                        attributeValue = String.init(data: Data.init(base64Encoded: tempAttributeValue)!, encoding: String.Encoding.utf8) ?? ""
                    } else {
                        attributeValue = ""
                    }
                }

                // escape double quote
                attributeValue = attributeValue.replacingOccurrences(of: "\"", with: "\"\"")

                // save attribute value or append it to the existing
                if let val = record[attributeName] {
                    //record[attributeName] = "\"" + val.substringWithRange(Range<String.Index>(start: val.startIndex.successor(), end: val.endIndex.predecessor())) + ";" + attributeValue + "\""
                    record[attributeName] = val + ";" + attributeValue
                } else {
                    record[attributeName] = attributeValue
                }
            }
        }
        // save last record
        if record.count > 0 {
            records.append(record)
        }

        return records
    }

    /// FreeIPA / 389-DS RootDSE returns multiple `namingContexts` values
    /// (the domain suffix, plus `o=ipaca` for the CA backend and
    /// `cn=changelog` for replication). cleanLDIF() folds repeated values
    /// for the same attribute together with ";" - correct for genuinely
    /// multi-valued attributes like memberOf, but wrong here, since it
    /// produces something like "dc=example,dc=com;cn=changelog;o=ipaca"
    /// which is not a usable search base. Pick out just the actual domain
    /// suffix (the "dc=" one that isn't cn=changelog/o=ipaca).
    fileprivate func selectDomainNamingContext(_ raw: String) -> String {
        let candidates = raw.components(separatedBy: ";")
        if candidates.count == 1 {
            return raw
        }
        for candidate in candidates {
            let lower = candidate.lowercased()
            if lower.hasPrefix("dc=") && !lower.contains("cn=changelog") {
                return candidate
            }
        }
        // fallback: first candidate if nothing matched the dc= pattern
        return candidates.first ?? raw
    }

    fileprivate func getAttributeForSingleRecordFromCleanedLDIF(_ attribute: String, ldif: [[String:String]]) -> String {
        var result: String = ""

        var foundAttribute = false

        for record in ldif {
            for (key, value) in record {
                if attribute == key {
                    foundAttribute = true
                    result = value
                    break;
                }
            }
            if (foundAttribute == true) {
                break;
            }
        }
        return result
    }

    fileprivate func getAttributesForSingleRecordFromCleanedLDIF(_ attributes: [String], ldif: [[String:String]]) -> [String:String] {
        var results = [String: String]()

        var foundAttribute = false
        for record in ldif {
            for (key, value) in record {
                if attributes.contains(key) {
                    foundAttribute = true
                    results[key] = value
                }
            }
            if (foundAttribute == true) {
                break;
            }
        }
        return results
    }

    fileprivate func cleanLDAPResultsMultiple(_ result: String, attribute: String) -> String {
        let lines = result.components(separatedBy: "\n")

        var myResult = ""

        for i in lines {
            if (i.contains(attribute)) {
                if myResult == "" {
                    myResult = i.replacingOccurrences( of: attribute + ": ", with: "")
                } else {
                    myResult = myResult + (", " + i.replacingOccurrences( of: attribute + ": ", with: ""))
                }
            }
        }
        return myResult
    }

    // private function that uses netcat to create a socket connection to the LDAP server to see if it's reachable.
    // using ldapsearch for this can take a long time to timeout, this returns much quicker

    fileprivate func testSocket( _ host: String ) -> Bool {

        let mySocketResult = cliTask("/usr/bin/nc -G 5 -z " + host + " " + String(port))
        if mySocketResult.contains("succeeded!") {
            return true
        } else {
            return false
        }
    }

    // private function to test for an LDAP namingContexts entry from the LDAP server
    // this tests for LDAP connectivity and gets the default naming context at the same time

    fileprivate func testLDAP ( _ host: String ) -> Bool {

        // FreeIPA/389-DS RootDSE exposes "namingContexts", not AD's
        // "defaultNamingContext".
        let attribute = "namingContexts"

        var myLDAPResult = ""

        if anonymous {
            myLDAPResult = cliTask("/usr/bin/ldapsearch -N -LLL -x " + maxSSF + "-l 3 -s base -H " + URIPrefix + host + " " + attribute)
        } else {
            myLDAPResult = cliTask("/usr/bin/ldapsearch -N -LLL -Q " + maxSSF + "-l 3 -s base -H " + URIPrefix + host + " " + attribute)
        }

        if myLDAPResult != "" && !myLDAPResult.contains("GSSAPI Error") && !myLDAPResult.contains("Can't contact") {
            let ldifResult = cleanLDIF(myLDAPResult)
            if ( ldifResult.count > 0 ) {
                defaultNamingContext = selectDomainNamingContext(getAttributeForSingleRecordFromCleanedLDIF(attribute, ldif: ldifResult))
                return true
            }
        }
        return false
    }

    // MARK: Kerberos preference file needs to be updated:
    // This function builds new Kerb prefs with KDC included if possible

    private func checkKpasswdServer() -> Bool {
        if hosts.isEmpty {
            TCSLogWithMark("Make sure we have LDAP servers")
            getHosts(domain)
        }

        TCSLogWithMark("Searching for kerberos srv records")

        let myKpasswdServers = getSRVRecords(domain, srv_type: "_kpasswd._tcp.")
        TCSLogWithMark("New kpasswd Servers are: " + myKpasswdServers.description)
        TCSLogWithMark("Current Server is: " + currentServer)

        if myKpasswdServers.contains(currentServer) {
            TCSLogWithMark("Found kpasswd server that matches current LDAP server.")
            TCSLogWithMark("Attempting to set kpasswd server to ensure Kerberos and LDAP are in sync.")

            // get the defaults for com.apple.Kerberos
            let kerbPrefs = UserDefaults.init(suiteName: "com.apple.Kerberos")

            // get the list defaults, or create an empty dictionary if there are none
            let kerbDefaults = kerbPrefs?.dictionary(forKey: "libdefaults") ?? [String:AnyObject]()

            // test to see if the domain_defaults key already exists, if not build it
            if kerbDefaults["default_realm"] != nil {
                TCSLogWithMark("Existing default realm. Skipping adding default realm to Kerberos prefs.")
            } else {
                // build a dictionary and add the KDC into it then write it back to defaults
                let libDefaults = NSMutableDictionary()
                libDefaults.setValue(kerberosRealm, forKey: "default_realm")
                kerbPrefs?.set(libDefaults, forKey: "libdefaults")
            }

            // get the list of domains, or create an empty dictionary if there are none
            var kerbRealms = kerbPrefs?.dictionary(forKey: "realms")  ?? [String:AnyObject]()

            // test to see if the realm already exists, if not build it
            if kerbRealms[kerberosRealm] != nil {
                TCSLogWithMark("Existing Kerberos configuration for realm. Skipping adding KDC to Kerberos prefs.")
                return false
            } else {
                // build a dictionary and add the KDC into it then write it back to defaults
                let realm = NSMutableDictionary()
                //realm.setValue(myLDAPServers.currentServer, forKey: "kdc")
                realm.setValue(currentServer, forKey: "kpasswd_server")
                kerbRealms[kerberosRealm] = realm
                kerbPrefs?.set(kerbRealms, forKey: "realms")
                return true
            }
        } else {
            myLogger.logit(LogLevel.base, message: "Couldn't find kpasswd server that matches current LDAP server. Letting system chose.")
            return false
        }
    }

    // calculate password complexity (minimum length) via the user's
    // krbPwdPolicyReference, falling back to the realm's global policy.

    fileprivate func getComplexity(pso: String="") -> Int? {

        if pso == "" {
            // no specific policy reference for the user, get the realm's
            // global password policy: cn=global_policy,cn=<REALM>,cn=kerberos,<basedn>

            let tempDefault = defaultNamingContext
            defaultNamingContext = "cn=global_policy,cn=\(kerberosRealm),cn=kerberos," + defaultNamingContext

            let result = try? getLDAPInformation([ "krbPwdMinLength"], baseSearch: true, searchTerm: "", test: true, overrideDefaultNamingContext: true)

            defaultNamingContext = tempDefault

            if result == nil {
                return nil
            }

            let resultClean = getAttributesForSingleRecordFromCleanedLDIF([ "krbPwdMinLength"], ldif: result!)

            let final = resultClean[ "krbPwdMinLength"] ?? ""

            if final == "" {
                return nil
            } else {
                return Int(final)
            }
        } else {
            // go get the policy entry referenced by krbPwdPolicyReference

            let tempDefault = defaultNamingContext

            defaultNamingContext = pso

            let result = try? getLDAPInformation(["krbPwdMinLength"], baseSearch: false, searchTerm: "(objectClass=krbPwdPolicy)", overrideDefaultNamingContext: true)
            // set the default naming context back

            defaultNamingContext = tempDefault

            if result == nil {
                return nil
            }

            let resultClean = getAttributesForSingleRecordFromCleanedLDIF([ "krbPwdMinLength"], ldif: result!)
            let final = resultClean["krbPwdMinLength"] ?? ""

            if final == "" {
                return nil
            } else {
                return Int(final)
            }
        }
    }

    // Remove a default realm from the Kerb pref file

    fileprivate func cleanKerbPrefs(clearLibDefaults: Bool=false) {

        // get the defaults for com.apple.Kerberos

        let kerbPrefs = UserDefaults.init(suiteName: "com.apple.Kerberos")

        // get the list of domains, or create an empty dictionary if there are none

        var kerbRealms = kerbPrefs?.dictionary(forKey: "realms")  ?? [String:AnyObject]()

        // test to see if the realm already exists, if it's already gone we are good

        if kerbRealms[kerberosRealm] == nil {
            TCSLogWithMark("No realm in com.apple.Kerberos defaults.")
        } else {
            TCSLogWithMark("Removing realm from Kerberos Preferences.")
            // remove the realm from the realms list
            kerbRealms.removeValue(forKey: kerberosRealm)
            // save the dictionary back to the pref file
            kerbPrefs?.set(kerbRealms, forKey: "realms")

            if clearLibDefaults {
                var libDefaults = kerbPrefs?.dictionary(forKey: "libdefaults")  ?? [String:AnyObject]()
                libDefaults.removeValue(forKey: "default_realm")
                kerbPrefs?.set(libDefaults, forKey: "libdefaults")
            }
        }
    }


}
@available(macOS, deprecated: 11)
extension NoMADSession: NoMADUserSession {

    public func getKerberosTicket(principal: String? = nil, completion: @escaping (KerberosTicketResult) -> Void) {
        // Check if system already has tickets
        if let principal = principal, klistUtil.hasTickets(principal: principal) {
            shareKerberosResult(completion: completion)
            return
        }

        KerbUtil().getKerberosCredentials(userPass, userPrincipal) {  errorDict in
            self.userPass = ""
            if let errorDict = errorDict {
                self.state = .kerbError
                let sessionError: NoMADSessionError

                let errorValue = errorDict["NSDescription"] as? String ?? "Unknown error"

                switch errorValue {
                case NoMADSessionError.PasswordExpired.rawValue:
                    sessionError = .PasswordExpired
                case NoMADSessionError.wrongRealm.rawValue:
                    sessionError = .wrongRealm
                case _ where errorValue.contains("unable to reach any KDC in realm"):
                    sessionError = .OffDomain
                default:
                    sessionError = .KerbError
                }
                completion(.failure(sessionError))
            } else {
                self.processKerberosResult(completion: completion)
            }
        }
    }

    private func processKerberosResult(completion: @escaping (KerberosTicketResult) -> Void) {
        state = .offDomain

        // Get ticket
        klistUtil.klist()

        // Check that ticket is valid
        if !klistUtil.returnDefaultPrincipal().contains(kerberosRealm) && !anonymous {
            completion(.failure(.UnAuthenticated))
            return
        }

        if useSSL {
            URIPrefix = "ldaps://"
            port = 636
            maxSSF = "-O maxssf=0 "
        }

        if let server = siteManager.sites[domain] {
            // use existing server
            hosts = server
            state = .success
        } else {
            getHosts(domain)
            guard !hosts.isEmpty else {
                completion(.failure(.OffDomain))
                return
            }
            // write found server back to site manager (cache key retained
            // for compatibility - "site" here just means "known-good server set")
            siteManager.sites[domain] = hosts
        }
        testHosts()
        shareKerberosResult(completion: completion)
    }

    private func shareKerberosResult(completion: (KerberosTicketResult) -> Void) {
        let result: KerberosTicketResult
        if let userRecord = userRecord {
            result = .success(userRecord)
        } else {
            result = .failure(.KerbError)
        }
        completion(result)
    }

    /// Function to authenticate a user via Kerberos. If only looking to test the password, and not get a ticket, pass (authTestOnly: true).
    ///
    /// Note this will kill any pre-existing tickets for this user as well.
    ///
    /// - Parameter authTestOnly: Should this authentication attempt only validate the password without getting Kerberos tickets? Defaults to `false`.
    public func authenticate(authTestOnly: Bool = false) {
        // authenticate
        let kerbUtil = KerbUtil()
//        let kerbError = kerbUtil.getKerbCredentials(userPass, userPrincipal)

        kerbUtil.getKerberosCredentials(userPass, userPrincipal) { errorDict in
            // scrub the password field
            self.userPass = ""

            if let errorDict = errorDict as? Dictionary<String,Any>,
               let description = errorDict[GSSErrorKey.descriptionKey.rawValue] as? String,
               let majorErrorCode = errorDict[GSSErrorKey.majorErrorCodeKey.rawValue] as? Int,
               let minorErrorCode = errorDict[GSSErrorKey.minorErrorCodeKey.rawValue] as? NSNumber,
               let mechanism = errorDict[GSSErrorKey.mechanismKey.rawValue] as? String,
               let mechanismOID = errorDict[GSSErrorKey.mechanismOIDKey.rawValue] as? String

            {
                let error = GSSError(mechanism: mechanism, mechanismOID: mechanismOID, majorErrorCode: majorErrorCode, minorErrorCode: UInt(UInt32(truncating:minorErrorCode)), description: description)

                // error
                self.state = .kerbError

                switch error.description {
                case "Password has expired" :
                    self.delegate?.NoMADAuthenticationFailed(error: NoMADSessionError.PasswordExpired, description: error.description)
                    break
                case "Wrong realm" :
                    self.delegate?.NoMADAuthenticationFailed(error: NoMADSessionError.wrongRealm, description: error.description)
                    break
                case _ where error.description.range(of: "unable to reach any KDC in realm") != nil :
                    self.delegate?.NoMADAuthenticationFailed(error: NoMADSessionError.OffDomain, description: error.description)
                    break
                default:
                    //user not found
                    if error.majorErrorCode == 0x0D0000, error.minorErrorCode == 0x96C73A06, mechanismOID == "1 2 840 113554 1 2 2" {
                        self.delegate?.NoMADAuthenticationFailed(error: NoMADSessionError.UnknownPrincipal, description: error.description)

                        return
                    }
                    //other error
                    self.delegate?.NoMADAuthenticationFailed(error: NoMADSessionError.KerbError, description: error.description)
                }
            } else {
                if authTestOnly {
                    klistUtil.kdestroy(princ: self.userPrincipal)
                }
                self.delegate?.NoMADAuthenticationSucceeded()
            }
        }

    }

    /// Change the password for the current user session via closure
//    public func changePassword(oldPassword: String, newPassword: String, completion: @escaping (String?) -> Void) {
//        TCSLogWithMark("Change Kerberos password")
//        KerbUtil().changeKerberosPassword(oldPassword, newPassword, userPrincipal) {
//            if let errorValue = $0 {
//                completion(errorValue)
//            } else {
//                completion(nil)
//            }
//        }
//    }

    /// Change the password for the current user session via delegate.
    ///
    public func changeKerberosPassword() throws {
        // change user's password
        // check kerb prefs - otherwise we can get an error here if not set
        TCSLogWithMark("Checking kpassword server.")

        _ = checkKpasswdServer()

        // set up the KerbUtil
        TCSLogWithMark("Init KerbUtil.")

        let kerbUtil = KerbUtil()
        TCSLogWithMark("Change password for userPrincipal: \(userPrincipal)")

        try kerbUtil.changeKerberosPassword(oldPass, newPass, userPrincipal)


        // If the password change worked then we are online. Reauthenticate with new password.
        //should update keychain here if we are in userspace

        self.oldPass = ""
        self.newPass = ""


        // clean the kerb prefs so we don't reuse the KDCs
        self.cleanKerbPrefs()
    }



    public func userInfo() {
        // set state to offDomain on start
        state = .offDomain

        // check for valid ticket
        klistUtil.klist()
        if !klistUtil.returnDefaultPrincipal().contains(kerberosRealm) && !anonymous {

            // no ticket for realm
            delegate?.NoMADAuthenticationFailed(error: NoMADSessionError.UnAuthenticated, description: "No ticket for Kerberos realm \(kerberosRealm)")
            return
        }

        // now some setup
        if useSSL {
            URIPrefix = "ldaps://"
            port = 636
            maxSSF = "-O maxssf=0 "
        }

        var lookupServers = true

        // check for connectivity and a previously cached server set
        if let server = siteManager.sites[domain] {
            // we have an existing server set, let's use it
            lookupServers = false
            hosts = server
        }

        if lookupServers {
            getHosts(domain)
        } else {
            state = .success
        }

        // if no LDAP servers, we're off the domain so bail
        if hosts.count == 0 {
            var errorMessage = "No LDAP servers can be reached."
            switch ldaptype {
            case .AD: errorMessage = "No FreeIPA servers can be reached."
            case .OD: errorMessage = "No Open Directory servers can be reached."
            }
            delegate?.NoMADAuthenticationFailed(error: NoMADSessionError.OffDomain, description: errorMessage)
            return
        }

        testHosts()
        if lookupServers {
            // write found server set back to the cache
            siteManager.sites[domain] = hosts
        }

        if getUserInformation()==false {
            delegate?.NoMADAuthenticationFailed(error: NoMADSessionError.UnknownPrincipal, description: "Invalid user account")
            return
        }

        // return the userRecord unless we came back empty
        if userRecord != nil {
            delegate?.NoMADUserInformation(user: userRecord!)
        }
    }
}
@available(macOS, deprecated: 11)
extension NoMADSession {
    // MARK: - testHosts with completion functionality

//    public func testHosts(completion: @escaping (Bool) -> Void) {
//
//        let dispatchGroup = DispatchGroup()
//
//        if state == .success {
//            for i in 0...( hosts.count - 1) {
//                dispatchGroup.enter()
//                if hosts[i].status != "dead" {
//                    myLogger.logit(.info, message:"Trying host: " + hosts[i].host)
//
//                    // socket test first - this could be falsely negative
//                    // also note that this needs to return stderr
//
//                    let cliTaskString = "/usr/bin/nc -G 5 -z " + hosts[i].host + " " + String(port)
//                    cliTask(cliTaskString) { result in
//                        self.handleSocketResult(result: result, index: i) {
//                            dispatchGroup.leave()
//                        }
//                    }
//                }
//            }
//        } else {
//            myLogger.logit(.base, message: "status not success but \(state) \n")
//            completion(false)
//        }
//        dispatchGroup.notify(queue: DispatchQueue.global()) {
//            myLogger.logit(.base, message: "Notifying that testHost groups dispatchGroup has finished their tasks")
//            completion(self.assertDomainStatus(assertionHosts: self.hosts))
//        }
//    }

    private func assertDomainStatus(assertionHosts: [NoMADLDAPServer]) -> Bool {
        guard (assertionHosts.count > 0) else {
            myLogger.logit(.base, message: "no hosts")
            return false
        }

        if assertionHosts.last!.status == "dead" {
            myLogger.logit(.base, message: "All IPA servers are dead! You should really fix this.")
            state = .offDomain
            return false
        } else {
            myLogger.logit(.base, message: "on domain!")
            state = .success
            return true
        }
    }

    private func handleSocketResult(result: String, index: Int, completion: @escaping () -> Void) {
        if result.contains("succeeded!") {

            // FreeIPA / 389-DS RootDSE attribute, not AD's "defaultNamingContext"
            let attribute = "namingContexts"

            if anonymous {
                let anonymusCliTaskCommand = "/usr/bin/ldapsearch -N -LLL -x " + maxSSF + "-l 3 -s base -H " + URIPrefix + hosts[index].host + " " + String(port) + " " + attribute
                cliTask(anonymusCliTaskCommand) { result in
                    self.handleSocketResultInternalCliTasks(result: result, index: index, attribute: attribute)
                    completion()
                }
            } else {
                let nonanonymusCliTaskCommand = "/usr/bin/ldapsearch -N -LLL -Q " + maxSSF + "-l 3 -s base -H " + URIPrefix + hosts[index].host + " " + String(port) + " " + attribute
                cliTask(nonanonymusCliTaskCommand) { result in
                    self.handleSocketResultInternalCliTasks(result: result, index: index, attribute: attribute)
                    completion()
                }
            }
            return
        } else {
            myLogger.logit(.info, message:"Server is dead by way of socket test: " + hosts[index].host)
            hosts[index].status = "dead"
            hosts[index].timeStamp = Date()
            completion()
        }
    }

    private func handleSocketResultInternalCliTasks(result: String, index: Int, attribute: String) {
        if result != "" && !result.contains("GSSAPI Error") && !result.contains("Can't contact") {
            let ldifResult = cleanLDIF(result)
            if ( ldifResult.count > 0 ) {
                defaultNamingContext = selectDomainNamingContext(getAttributeForSingleRecordFromCleanedLDIF(attribute, ldif: ldifResult))
                hosts[index].status = "live"
                hosts[index].timeStamp = Date()
                myLogger.logit(.base, message:"Current LDAP Server is: " + hosts[index].host )
                myLogger.logit(.base, message:"Current default naming context: " + defaultNamingContext )
                current = index
                return
            }
        }
        // We didn't get an actual LDIF Result... so LDAP isn't working.
        myLogger.logit(.info, message:"Server is dead by way of ldap test: " + hosts[index].host)
        hosts[index].status = "dead"
        hosts[index].timeStamp = Date()
    }
}
