// Copyright 2026 The Hanzo Authors. All Rights Reserved.
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
import {Minus, Plus, ShoppingCart} from "lucide-react";
import {Button} from "../../components/ui/button";
import {Input} from "../../components/ui/input";
import {cn} from "../../lib/utils";

export class QuantityStepper extends React.Component {
  render() {
    const {value, onIncrease, onDecrease, onChange, min = 1, max, disabled, className, style} = this.props;

    const parsedValue = (value === null || value === undefined || value === "") ? NaN : Number(value);
    const normalizedValue = Number.isFinite(parsedValue) ? parsedValue : min;

    return (
      <div
        className={cn("inline-flex items-center border border-input rounded-md h-9 overflow-hidden", className)}
        style={style}
      >
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="h-full w-1/3 rounded-none"
          disabled={disabled || normalizedValue <= min}
          onClick={onDecrease}
        >
          <Minus className="h-4 w-4" />
        </Button>

        <Input
          type="number"
          min={min}
          max={max}
          value={normalizedValue}
          onChange={(e) => onChange?.(Number(e.target.value))}
          disabled={disabled}
          className={cn(
            "w-1/3 h-full text-center border-0 rounded-none focus-visible:ring-0 focus-visible:ring-offset-0 shadow-none",
            !onChange && "pointer-events-none",
          )}
        />

        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="h-full w-1/3 rounded-none"
          disabled={disabled || (max !== undefined && normalizedValue >= max)}
          onClick={onIncrease}
        >
          <Plus className="h-4 w-4" />
        </Button>
      </div>
    );
  }
}

export class FloatingCartButton extends React.Component {
  render() {
    const {itemCount, onClick} = this.props;

    return (
      <div
        style={{position: "fixed", bottom: "50px", right: "50px", zIndex: 1000, cursor: "pointer"}}
        onClick={onClick}
      >
        <div className="relative">
          <Button
            type="button"
            size="icon"
            className="rounded-full w-[60px] h-[60px] shadow-lg"
          >
            <ShoppingCart style={{width: 24, height: 24}} />
          </Button>
          {itemCount > 0 && (
            <span className="absolute -top-1 -right-1 min-w-[20px] h-[20px] px-1 rounded-full bg-destructive text-destructive-foreground text-xs font-semibold flex items-center justify-center">
              {itemCount}
            </span>
          )}
        </div>
      </div>
    );
  }
}
