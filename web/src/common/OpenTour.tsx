// Copyright 2023 The Hanzo Authors. All Rights Reserved.
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

// @ts-nocheck
import React from "react";
import {HelpCircle} from "lucide-react";
import {Tooltip, TooltipContent, TooltipProvider, TooltipTrigger} from "../components/ui/tooltip";
import * as TourConfig from "../TourConfig";
import * as Setting from "../Setting";

// TODO(rip-antd): Tour walkthrough disabled — needs driver.js or similar.
// The icon + tooltip remain so the slot in the UI is preserved; clicking
// it currently flips TourConfig state but nothing renders the overlay.

class OpenTour extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      isTourVisible: props.isTourVisible ?? TourConfig.getTourVisible(),
    };
  }

  canTour = () => {
    const path = window.location.pathname.replace("/", "");
    return TourConfig.TourUrlList.indexOf(path) !== -1 || path === "";
  };

  render() {
    const hidden = Setting.isMobile();

    if (this.canTour()) {
      return (
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <div
                className="select-box"
                style={{display: hidden ? "none" : undefined, ...this.props.style}}
                onClick={() => TourConfig.setIsTourVisible(true)}
              >
                <HelpCircle style={{width: 24, height: 24}} />
              </div>
            </TooltipTrigger>
            <TooltipContent>Click to open tour</TooltipContent>
          </Tooltip>
        </TooltipProvider>
      );
    }

    return (
      <div
        className="select-box"
        style={{display: hidden ? "none" : undefined, cursor: "not-allowed", ...this.props.style}}
      >
        <HelpCircle style={{width: 24, height: 24, color: "#adadad"}} />
      </div>
    );
  }
}

export default OpenTour;
