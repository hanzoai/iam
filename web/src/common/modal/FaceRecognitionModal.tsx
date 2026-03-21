// Copyright 2024 The Hanzo Authors. All Rights Reserved.
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

import * as faceapi from "face-api.js";
import React, {useState} from "react";
import {Loader2} from "lucide-react";
import i18next from "i18next";
import * as Setting from "../../Setting";

const FaceRecognitionModal = (props: any) => {
  const {visible, onOk, onCancel, withImage} = props;
  const [modelsLoaded, setModelsLoaded] = React.useState(false);
  const [isCameraCaptured, setIsCameraCaptured] = useState(false);

  const videoRef = React.useRef<HTMLVideoElement>(null);
  const canvasRef = React.useRef<HTMLCanvasElement>(null);
  const detection = React.useRef<any>(null);
  const mediaStreamRef = React.useRef<MediaStream | null>(null);
  const [percent, setPercent] = useState(0);

  const [files, setFiles] = useState<any[]>([]);
  const [currentFaceId, setCurrentFaceId] = React.useState<any>();
  const [currentFaceIndex, setCurrentFaceIndex] = React.useState<number>();

  React.useEffect(() => {
    if (!visible || modelsLoaded) {
      return;
    }

    const loadModels = async () => {
      const MODEL_URL = `${Setting.StaticBaseUrl}/iam/models`;

      Promise.all([
        faceapi.nets.tinyFaceDetector.loadFromUri(MODEL_URL),
        faceapi.nets.faceLandmark68Net.loadFromUri(MODEL_URL),
        faceapi.nets.faceRecognitionNet.loadFromUri(MODEL_URL),
      ]).then(() => {
        setModelsLoaded(true);
      }).catch(() => {
        Setting.showMessage("error", i18next.t("login:Model loading failure"));
        onCancel();
      });
    };
    loadModels();
  }, [visible, modelsLoaded]);

  React.useEffect(() => {
    if (withImage) {
      return;
    }
    if (visible) {
      setPercent(0);
      if (modelsLoaded) {
        navigator.mediaDevices
          .getUserMedia({video: {facingMode: "user"}})
          .then((stream) => {
            mediaStreamRef.current = stream;
            setIsCameraCaptured(true);
          }).catch((error) => {
            handleCameraError(error);
          });
      }
    } else {
      clearInterval(detection.current);
      detection.current = null;
      setIsCameraCaptured(false);
    }
    return () => {
      clearInterval(detection.current);
      detection.current = null;
      setIsCameraCaptured(false);
    };
  }, [visible, modelsLoaded]);

  React.useEffect(() => {
    if (withImage) {
      return;
    }
    if (isCameraCaptured) {
      let count = 0;
      const interval = setInterval(() => {
        count++;
        if (videoRef.current) {
          videoRef.current.srcObject = mediaStreamRef.current;
          videoRef.current.play();
          clearInterval(interval);
        }
        if (count >= 30) {
          clearInterval(interval);
          onCancel();
        }
      }, 100);
    } else {
      mediaStreamRef.current?.getTracks().forEach(track => track.stop());
      if (videoRef.current) {
        videoRef.current.srcObject = null;
      }
    }
  }, [isCameraCaptured]);

  const handleStreamVideo = () => {
    if (withImage) {
      return;
    }
    let count = 0;
    let goodCount = 0;
    if (!detection.current) {
      detection.current = setInterval(async () => {
        if (modelsLoaded && videoRef.current && visible) {
          const faces = await faceapi.detectAllFaces(videoRef.current, new faceapi.TinyFaceDetectorOptions()).withFaceLandmarks().withFaceDescriptors();

          count++;
          if (count % 50 === 0) {
            Setting.showMessage("info", i18next.t("login:Please ensure sufficient lighting and align your face in the center of the recognition box"));
          } else if (count > 300) {
            Setting.showMessage("error", i18next.t("login:Face recognition failed"));
            onCancel();
          }
          if (faces.length === 1) {
            const face = faces[0];
            setPercent(Math.round(face.detection.score * 100));
            const array = Array.from(face.descriptor);
            if (face.detection.score > 0.9) {
              goodCount++;
              if (face.detection.score > 0.99 || goodCount > 10) {
                clearInterval(detection.current);
                onOk(array);
              }
            }
          } else {
            setPercent((prev: number) => Math.round(prev / 2));
          }
        }
      }, 100);
    }
  };

  const handleCameraError = (error: any) => {
    onCancel();
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

  const getBase64 = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.readAsDataURL(file);
      reader.onload = () => resolve(reader.result as string);
      reader.onerror = (error) => reject(error);
    });
  };

  if (!withImage) {
    if (!visible || !isCameraCaptured) {
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
            {modelsLoaded ? (
              <div className="flex justify-center items-center relative">
                <video
                  ref={videoRef}
                  onPlay={handleStreamVideo}
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
            ) : (
              <div className="flex justify-center items-center py-8">
                <Loader2 className="w-8 h-8 text-white animate-spin" />
                <span className="ml-2 text-gray-400 text-sm">{i18next.t("login:Loading")}</span>
              </div>
            )}
          </div>

          <div className="flex justify-end gap-2 mt-6">
            <button onClick={onCancel} className="px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors">
              {i18next.t("general:Cancel")}
            </button>
          </div>
        </div>
      </div>
    );
  }

  // withImage mode
  if (!visible) {
    return null;
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80">
      <div className="bg-[#0a0a0a] border border-white/10 rounded-xl p-6 w-[350px]">
        <h2 className="text-lg font-semibold text-white mb-4">{i18next.t("login:Face Recognition")}</h2>

        <div className="space-y-3">
          <div
            className="border-2 border-dashed border-white/20 rounded-lg p-6 text-center cursor-pointer hover:border-white/40 transition-colors"
            onClick={() => {
              const input = document.createElement("input");
              input.type = "file";
              input.multiple = true;
              input.accept = "image/*";
              input.onchange = async (e) => {
                const target = e.target as HTMLInputElement;
                if (target.files) {
                  const newFiles = [...files];
                  for (const file of Array.from(target.files)) {
                    const base64 = await getBase64(file);
                    (file as any).base64 = base64;
                    newFiles.push(file);
                  }
                  setFiles(newFiles);
                  setCurrentFaceId([]);
                }
              };
              input.click();
            }}
          >
            <p className="text-gray-400 text-sm">{i18next.t("general:Click to Upload")}</p>
          </div>

          {files.length > 0 && (
            <div className="space-y-1">
              {files.map((file, idx) => (
                <div key={idx} className="flex items-center justify-between text-sm text-gray-300 px-2 py-1 bg-white/5 rounded">
                  <span className="truncate">{file.name}</span>
                  <button
                    onClick={() => {
                      const newFiles = files.filter((_, i) => i !== idx);
                      setFiles(newFiles);
                      setCurrentFaceId([]);
                    }}
                    className="text-gray-500 hover:text-red-400 ml-2"
                  >
                    &times;
                  </button>
                </div>
              ))}
            </div>
          )}

          {modelsLoaded && (
            <button
              className="w-full px-4 py-2 text-sm border border-white/20 text-white rounded-lg hover:bg-white/10 transition-colors"
              onClick={async () => {
                let maxScore = 0;
                for (const file of files) {
                  const fileIndex = files.indexOf(file);
                  const img = new Image();
                  img.src = file.base64;
                  const faceIds = await faceapi.detectAllFaces(img, new faceapi.TinyFaceDetectorOptions()).withFaceLandmarks().withFaceDescriptors();
                  if (faceIds[0]?.detection.score > 0.9 && faceIds[0]?.detection.score > maxScore) {
                    maxScore = faceIds[0]?.detection.score;
                    setCurrentFaceId(faceIds[0]);
                    setCurrentFaceIndex(fileIndex);
                  }
                }
                if (maxScore < 0.9) {
                  Setting.showMessage("error", i18next.t("login:Face recognition failed"));
                }
              }}
            >
              {i18next.t("general:Generate")}
            </button>
          )}
        </div>

        {currentFaceId && currentFaceId.length !== 0 && currentFaceIndex !== undefined && (
          <div className="mt-3">
            <div className="text-sm text-gray-400">{i18next.t("application:Select")}: {files[currentFaceIndex]?.name}</div>
            <img src={files[currentFaceIndex]?.base64} alt="selected" className="w-full mt-2 rounded" />
          </div>
        )}

        <div className="flex justify-end gap-2 mt-6">
          <button
            onClick={() => {
              onOk(Array.from(currentFaceId.descriptor));
            }}
            disabled={!currentFaceId || currentFaceId?.length === 0}
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

export default FaceRecognitionModal;
