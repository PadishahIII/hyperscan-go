# Overview
Using hyperscan in golang to extract pictures and regex over **network traffic**.
- Utilize stream mode of hyperscan which can fit network traffic environment better
- StreamBuffer.go: manage the lifecycle of `Stream`
- main.go: perform hyperscan matching
- patterns.txt: regex defination
