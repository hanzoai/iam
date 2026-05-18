// @ts-nocheck
import {Lock} from "lucide-react";
import i18next from "i18next";
import React, {useState} from "react";
import {Button} from "../../components/ui/button";
import {Input} from "../../components/ui/input";
import * as UserBackend from "../../backend/UserBackend";

function CheckPasswordForm({user, onSuccess, onFail}) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const onSubmit = (e) => {
    e.preventDefault();
    if (!password) {
      setError(i18next.t("login:Please input your password!"));
      return;
    }
    setError("");
    setSubmitting(true);
    const data = {...user, password};
    UserBackend.checkUserPassword(data)
      .then((res) => {
        if (res.status === "ok") {
          onSuccess(res);
        } else {
          onFail(res);
        }
      })
      .finally(() => {
        setPassword("");
        setSubmitting(false);
      });
  };

  return (
    <form onSubmit={onSubmit} style={{width: "300px", marginTop: "20px"}}>
      <div className="relative">
        <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-500" />
        <Input
          type="password"
          value={password}
          onChange={(e) => { setPassword(e.target.value); setError(""); }}
          placeholder={i18next.t("general:Password")}
          className="pl-9"
        />
      </div>
      {error && <p className="text-sm text-red-500 mt-1">{error}</p>}
      <Button
        type="submit"
        disabled={submitting}
        className="mt-6 w-full"
      >
        {i18next.t("forget:Next Step")}
      </Button>
    </form>
  );
}

export default CheckPasswordForm;
