http-get "lurker" {

    set uri "/geturi";

    client {

        metadata {
            base64url;
            header "Cookie";
        }
    }

    server {
        output {
            base64url;
            print;
        }
    }
}

http-post "lurker" {

    set uri "/posturi";

    client {

        id {
            base64url;
            header "Cookie";
        }

        output {
            base64url;
            print;
        }
    }

    server {

        output {
            base64url;
            print;
        }
    }
}