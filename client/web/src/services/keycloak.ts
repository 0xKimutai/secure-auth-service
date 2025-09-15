import Keycloak from "keycloak-js";

const keycloak = new Keycloak({
  url: "http://localhost:8081/",
  realm: "authsystem",
  clientId: "authsystem-client",
});

export default keycloak;
