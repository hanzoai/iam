// Copyright 2025 The Hanzo Authors. All Rights Reserved.
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

import React, {useState} from "react";
import i18next from "i18next";
import * as Setting from "../../Setting";

const FaceRecognitionCommonModal = (props: any) => {
  const {visible, onOk, onCancel} = props;

  const videoRef = React.useRef<HTMLVideoElement>(null);
  const canvasRef = React.useRef<HTMLCanvasElement>(null);
  const [percent, setPercent] = useState(0);
  const mediaStreamRef = React.useRef<MediaStream | null>(null);
  const [isCameraCaptured, setIsCameraCaptured] = useState(false);
  const [capturedImageArray, setCapturedImageArray] = useState<string[]>([]);

  React.useEffect(() => {
    if (isCameraCaptured) {
      let count = 0;
      let count2 = 0;
      const interval = setInterval(() => {
        count++;
        if (videoRef.current) {
          videoRef.current.srcObject = mediaStreamRef.current;
          videoRef.current.play();
          const interval2 = setInterval(() => {
            if (!visible) {
              clearInterval(interval);
              setPercent(0);
            }
            count2++;
            if (count2 >= 8) {
              clearInterval(interval2);
              setPercent(0);
              onOk(capturedImageArray);
            } else if (count2 > 3) {
              setPercent((count2 - 4) * 20);
              const canvas = document.createElement("canvas");
              canvas.width = videoRef.current!.videoWidth;
              canvas.height = videoRef.current!.videoHeight;
              const context = canvas.getContext("2d")!;
              context.drawImage(videoRef.current!, 0, 0, canvas.width, canvas.height);
              const b64 = canvas.toDataURL("image/png");
              capturedImageArray.push(b64);
              setCapturedImageArray(capturedImageArray);
            }
          }, 1000);

          clearInterval(interval);
        }
        if (count >= 30) {
          clearInterval(interval);
        }
      }, 100);
    } else {
      mediaStreamRef.current?.getTracks().forEach(track => track.stop());
      if (videoRef.current) {
        videoRef.current.srcObject = null;
      }
    }
  }, [isCameraCaptured]);

  React.useEffect(() => {
    if (visible) {
      navigator.mediaDevices
        .getUserMedia({video: {facingMode: "user"}})
        .then((stream) => {
          mediaStreamRef.current = stream;
          setIsCameraCaptured(true);
        }).catch((error) => {
          handleCameraError(error);
        });
    } else {
      setIsCameraCaptured(false);
      setCapturedImageArray([]);
    }
  }, [visible]);

  const handleCameraError = (error: DOMException) => {
    if (error instanceof DOMException) {
      if (error.name === "NotFoundError" || error.name === "DevicesNotFoundError") {
        Setting.showMessage("error", i18next.t("login:Please ensure that you have a camera device for facial recognition"));
      } else if (error.name === "NotAllowedError" || error.name === "PermissionDeniedError") {
        Setting.showMessage("error", i18next.t("login:Please provide permission to access the camera"));
      } else if (error.name === "NotReadableError" || error.name === "TrackStartError") {
        Setting.showMessage("error", i18next.t("login:The camera is currently in use by another webpage"));
      } else if (error.name === "TypeError") {
        Setting.showMessage("error", i18next.t("login:Please load the webpage using HTTPS, otherwise the camera cannot be accessed"));
      } else {
        Setting.showMessage("error", error.message);
      }
    }
  };

  if (!visible) {
    return null;
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80">
      <div className="bg-[#0a0a0a] border border-white/10 rounded-xl p-6 w-[350px]">
        <h2 className="text-lg font-semibold text-white mb-4">{i18next.t("login:Face Recognition")}</h2>

        {/* Progress bar */}
        <div className="w-full bg-white/10 rounded-full h-2 mb-4">
          <div
            className="bg-white h-2 rounded-full transition-all duration-200"
            style={{width: `${percent}%`}}
          />
        </div>

        <div className="mt-5 mb-12 flex flex-col justify-center items-center relative">
          <div className="flex justify-center items-center relative">
            <video
              ref={videoRef}
              className="rounded-full h-[220px] w-[220px] object-cover align-middle"
            />
            <div className="absolute w-[240px] h-[240px] top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2">
              <svg width="240" height="240" fill="none">
                <circle
                  strokeDasharray="700"
                  strokeDashoffset={700 - 6.9115 * percent}
                  strokeWidth="4"
                  cx="120"
                  cy="120"
                  r="110"
                  stroke="#5734d3"
                  transform="rotate(-90, 120, 120)"
                  strokeLinecap="round"
                  style={{transition: "all .2s linear"}}
                />
              </svg>
            </div>
            <canvas ref={canvasRef} className="absolute" />
          </div>
        </div>

        <div className="flex justify-end gap-2 mt-6">
          <button
            onClick={() => onOk(capturedImageArray)}
            disabled={capturedImageArray.length === 0}
            className="px-4 py-2 text-sm bg-white text-black rounded-lg hover:bg-gray-200 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {i18next.t("general:OK")}
          </button>
          <button onClick={onCancel} className="px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors">
            {i18next.t("general:Cancel")}
          </button>
        </div>
      </div>
    </div>
  );
};

export default FaceRecognitionCommonModal;
