# AI Log Summarizer

## Overview
AI Log Summarizer is a lightweight Python tool that automatically pulls **Microsoft Defender alerts** through the Microsoft Graph Security API, summarizes them using an AI model, and outputs clear, actionable incident reports.  

Goal: help analysts or small IT teams quickly understand what happened, where, and what to do next—without manually parsing dozens of alerts.

---

## Features (MVP)
- ✅ Pulls the latest alerts from Microsoft Defender via Graph Security API  
- ✅ Normalizes alert data (title, description, severity, host, timestamp)  
- ✅ Summarizes alerts with an AI model (e.g., GPT-4-Turbo)  
- ✅ Outputs markdown or JSON reports  
- ✅ Runs locally—no external logging or cloud storage required  

---

## Project Structure
