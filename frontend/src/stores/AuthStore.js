// src/stores/AuthStore.js
import { makeAutoObservable } from "mobx";

class AuthStore {
    token = null;
    validator = null;
    pooling_station = null;
    publicKey = null;
    isAuth = false;
    isVoted = false;
    constructor() {
        makeAutoObservable(this);
    }
    setToken(token) {
        this.token = token;
    }
    setValidator(validator) {
        this.validator = validator;
    }
    setPollingStation(pollingStation) {
        this.pooling_station = pollingStation;
    }
    setPublicKey(publicKey) {
        this.publicKey = publicKey;
    }
    setIsAuth(isAuth) {
        this.isAuth = isAuth;
    }
    setIsVoted(isVoted) {
        this.isVoted = isVoted;
    }
}

export default new AuthStore();
