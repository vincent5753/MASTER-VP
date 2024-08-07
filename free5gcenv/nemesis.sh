#!/bin/bash

kubectl delete deployment --all
kubectl delete pod --all --grace-period=0 --force
sudo kubeadm reset -f
rm -rf ~/.kube
