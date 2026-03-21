// Copyright 2021 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import React, {useEffect, useRef, useState} from "react";
import Cropper from "react-cropper";
import "cropperjs/dist/cropper.css";
import * as Setting from "../../Setting";
import i18next from "i18next";
import * as ResourceBackend from "../../backend/ResourceBackend";

export const CropperDivModal = (props: any) => {
  const [loading, setLoading] = useState(true);
  const [options, setOptions] = useState<any[]>([]);
  const [image, setImage] = useState("");
  const [cropper, setCropper] = useState<any>();
  const [visible, setVisible] = useState(false);
  const [confirmLoading, setConfirmLoading] = useState(false);
  const {title, setTitle, tag, disabled, user, buttonText, organization} = props;
  const uploadButtonRef = useRef<HTMLInputElement>(null);

  const onChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    const files = e.target.files;
    if (!files || files.length === 0) {
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      setImage(reader.result as string);
    };
    if (!(files[0] instanceof Blob)) {
      return;
    }
    reader.readAsDataURL(files[0]);
  };

  const uploadAvatar = () => {
    cropper.getCroppedCanvas().toBlob((blob: Blob | null) => {
      if (blob === null) {
        Setting.showMessage("error", i18next.t("general:You must select a picture first"));
        return false;
      }
      const extension = image.substring(image.indexOf("/") + 1, image.indexOf(";base64"));
      const fullFilePath = `${tag}/${user.owner}/${user.name}.${extension}`;
      ResourceBackend.uploadResource(user.owner, user.name, tag, "CropperDivModal", fullFilePath, blob)
        .then((res: any) => {
          if (res.status === "ok") {
            window.location.href = window.location.pathname;
          } else {
            Setting.showMessage("error", res.msg);
          }
        });
      return true;
    });
  };

  const showModal = () => {
    setVisible(true);
  };

  const handleOk = () => {
    setConfirmLoading(true);
    uploadAvatar();
  };

  const handleCancel = () => {
    setVisible(false);
  };

  const selectFile = () => {
    uploadButtonRef.current?.click();
  };

  const getOptions = (data: any[]) => {
    const opts: any[] = [];
    opts.push({value: organization?.defaultAvatar, label: organization?.defaultAvatar});

    for (let i = 0; i < data.length; i++) {
      if (data[i].fileType === "image") {
        const url = `${data[i].url}`;
        opts.push({value: url, label: url});
      }
    }
    return opts;
  };

  const getBase64Image = (src: string) => {
    return new Promise<string>((resolve) => {
      const img = new Image();
      img.src = src;
      img.setAttribute("crossOrigin", "anonymous");
      img.onload = () => {
        const canvas = document.createElement("canvas");
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext("2d")!;
        ctx.drawImage(img, 0, 0, img.width, img.height);
        const dataURL = canvas.toDataURL("image/png");
        resolve(dataURL);
      };
    });
  };

  useEffect(() => {
    setLoading(true);
    ResourceBackend.getResources(user.owner, user.name, "", "", "", "", "", "")
      .then((res: any) => {
        if (res.status === "error") {
          Setting.showMessage("error", res.msg);
          setLoading(false);
          return;
        }
        setLoading(false);
        setOptions(getOptions(res));
      });
  }, []);

  return (
    <div>
      <button
        type="button"
        onClick={showModal}
        disabled={disabled}
        className="px-4 py-2 text-sm border border-white/20 text-white rounded-lg hover:bg-white/10 transition-colors disabled:opacity-50"
      >
        {buttonText}
      </button>
      {visible && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80">
          <div className="bg-[#0a0a0a] border border-white/10 rounded-xl p-6 w-[600px]">
            <h2 className="text-lg font-semibold text-white mb-4">{title}</h2>
            <div className="mx-auto w-full" style={{height: 350}}>
              <div className="w-full mb-5 space-y-2">
                <input
                  ref={uploadButtonRef}
                  type="file"
                  accept="image/*"
                  onChange={onChange}
                  className="hidden"
                />
                <button
                  onClick={selectFile}
                  className="w-full px-4 py-2 text-sm border border-white/20 text-white rounded-lg hover:bg-white/10 transition-colors"
                >
                  {i18next.t("user:Select a photo...")}
                </button>
                <select
                  className="w-full px-3 py-2 text-sm bg-transparent border border-white/20 rounded-lg text-white outline-none"
                  onChange={async (e) => {
                    if (e.target.value) {
                      setImage(await getBase64Image(e.target.value));
                    }
                  }}
                  defaultValue=""
                >
                  <option value="" disabled className="bg-[#0a0a0a]">
                    {loading ? "Loading..." : i18next.t("user:Please select avatar from resources")}
                  </option>
                  {options.map((opt, idx) => (
                    <option key={idx} value={opt.value} className="bg-[#0a0a0a]">
                      {opt.label}
                    </option>
                  ))}
                </select>
              </div>
              <Cropper
                style={{height: "100%"}}
                initialAspectRatio={1}
                preview=".img-preview"
                src={image}
                viewMode={1}
                guides={true}
                minCropBoxHeight={10}
                minCropBoxWidth={10}
                background={false}
                responsive={true}
                autoCropArea={1}
                checkOrientation={false}
                onInitialized={(instance: any) => {
                  setCropper(instance);
                }}
              />
            </div>
            <div className="flex justify-end mt-6">
              <button onClick={handleCancel} className="px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors mr-2">
                {i18next.t("general:Cancel")}
              </button>
              <button
                onClick={handleOk}
                disabled={confirmLoading}
                className="w-full px-4 py-2 text-sm bg-white text-black rounded-lg hover:bg-gray-200 transition-colors disabled:opacity-50"
              >
                {confirmLoading ? "..." : setTitle}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default CropperDivModal;
