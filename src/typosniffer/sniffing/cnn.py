class ImageComparator:
    def __init__(self):
        import torch
        from torchvision import models, transforms
    

        # Load pretrained model
        model = models.resnet50(weights='ResNet50_Weights.DEFAULT')
        model.share_memory()
        model.eval()
        
        self.feature_extractor = torch.nn.Sequential(*list(model.children())[:-1])

        # Preprocessing
        self.preprocess = transforms.Compose([
            transforms.Resize(256),
            transforms.ToTensor(),
            transforms.Normalize(mean=[0.485, 0.456, 0.406],
                                 std=[0.229, 0.224, 0.225])
        ])
        torch.set_num_threads(1)
        torch.set_num_interop_threads(1)


    def get_embedding(self, image):
        import torch
        image = image.convert("RGB")
        img_tensor = self.preprocess(image).unsqueeze(0)
        with torch.no_grad():
            features = self.feature_extractor(img_tensor)
            return features.flatten(1)

    def get_similarity(self, image1, image2):
        import torch.nn.functional as F
        emb1 = self.get_embedding(image1)
        emb2 = self.get_embedding(image2)
        return F.cosine_similarity(emb1, emb2)[0].item()
